import base64
import io
import json
import os
import re
from datetime import UTC, datetime, timedelta
from functools import wraps

import matplotlib
from flask import (
    Flask,
    Response,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_bcrypt import Bcrypt
from sqlalchemy import inspect, text
from werkzeug.middleware.proxy_fix import ProxyFix

from models import LoginLog, User, db

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def build_database_uri():
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        return "sqlite:///database.db"

    # Render and similar platforms often provide a postgresql:// URL. SQLAlchemy
    # should use the psycopg driver explicitly for this app's production config.
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)

    return database_url


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "smartiam-dev-key")
app.config["SQLALCHEMY_DATABASE_URI"] = build_database_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
app.config["PREFERRED_URL_SCHEME"] = "https"
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db.init_app(app)
bcrypt = Bcrypt(app)

CHATBOT_DEFAULT_SUGGESTIONS = [
    "How do I log in?",
    "Why was my account locked?",
    "What does High Risk mean?",
]
CHATBOT_HISTORY_LIMIT = 6
CHATBOT_OPENAI_MODEL = os.environ.get("OPENAI_CHATBOT_MODEL", "gpt-5.4-mini")

CHATBOT_TOPICS = [
    {
        "category": "Access",
        "title": "Login guidance",
        "tone": "info",
        "keywords": ["login", "log in", "sign in", "username", "credentials"],
        "reply": (
            "Use your registered username and password in the login form. If the account is active "
            "and the credentials are correct, SmartIAM opens the dashboard and records the session."
        ),
        "bullets": [
            "Enter the same username used during registration.",
            "Successful sign-ins are written to the audit log automatically.",
            "Suspicious sessions can still log in, but they may be flagged with a risk label.",
        ],
        "actions": [
            "How do I create an account?",
            "What does High Risk mean?",
        ],
        "suggestions": [
            "How do I create an account?",
            "What does High Risk mean?",
            "Why was my account locked?",
        ],
        "priority": 2,
    },
    {
        "category": "Onboarding",
        "title": "Create an account",
        "tone": "info",
        "keywords": ["register", "sign up", "create account", "new account", "registration"],
        "reply": (
            "Select Create account on the login page and enter a username, email, department, "
            "password, and role. SmartIAM supports both admin and user registrations."
        ),
        "bullets": [
            "Passwords must be at least 8 characters long.",
            "Each username and email must be unique in the system.",
            "Admins get monitoring and account-management controls after login.",
        ],
        "actions": [
            "What role should I choose?",
            "How do I log in?",
        ],
        "suggestions": [
            "What role should I choose?",
            "How do I log in?",
            "What can admins do?",
        ],
        "priority": 3,
    },
    {
        "category": "Roles",
        "title": "Admin and user permissions",
        "tone": "info",
        "keywords": ["role", "admin", "permissions", "user access", "privileges"],
        "reply": (
            "Admins can manage users, inspect logs, export reports, and review risk signals. "
            "Standard users can access their own dashboard, profile, and password tools."
        ),
        "bullets": [
            "Admin accounts can activate, suspend, or delete other users.",
            "User accounts focus on personal access and security history.",
            "Role selection happens during registration.",
        ],
        "actions": [
            "Can admins view risk alerts?",
            "Can I export logs?",
        ],
        "suggestions": [
            "What can admins do?",
            "Can admins view risk alerts?",
            "Can I export logs?",
        ],
        "priority": 2,
    },
    {
        "category": "Security",
        "title": "Account lock protection",
        "tone": "warning",
        "keywords": ["locked", "lock", "blocked", "failed attempts", "too many attempts"],
        "reply": (
            "SmartIAM can temporarily lock an account for 15 minutes after repeated failures or a "
            "high-risk pattern. This helps slow down brute-force activity."
        ),
        "bullets": [
            "Five failed attempts can trigger a temporary lock.",
            "A high-risk login pattern can also force a lock immediately.",
            "After the window ends, try again with the correct password or ask an admin to review the account.",
        ],
        "actions": [
            "How do I change my password?",
            "How does suspicious login detection work?",
        ],
        "suggestions": [
            "How does suspicious login detection work?",
            "How do I change my password?",
            "What does High Risk mean?",
        ],
        "priority": 4,
    },
    {
        "category": "Recovery",
        "title": "Password support",
        "tone": "info",
        "keywords": ["forgot password", "reset password", "change password", "password reset"],
        "reply": (
            "If you can still sign in, open the profile area and use Change Password. If you cannot "
            "access the account, an administrator should verify the account and unlock it first."
        ),
        "bullets": [
            "You need the current password to change it from the profile screen.",
            "New passwords must be at least 8 characters long.",
            "Locked accounts may need admin review before another attempt.",
        ],
        "actions": [
            "Why was my account locked?",
            "How do I log in?",
        ],
        "suggestions": [
            "Why was my account locked?",
            "How do I log in?",
            "What can admins do?",
        ],
        "priority": 3,
    },
    {
        "category": "Risk Engine",
        "title": "High Risk and Medium Risk alerts",
        "tone": "warning",
        "keywords": ["risk", "high risk", "medium risk", "suspicious", "unsafe", "anomaly"],
        "reply": (
            "Risk labels are generated from login behavior. High Risk reflects stronger warning signs, "
            "while Medium Risk indicates suspicious activity that is less severe."
        ),
        "bullets": [
            "Repeated failures, device changes, repeated IP activity, and off-hour attempts raise the score.",
            "High Risk can lead to lockouts or stronger warnings.",
            "Low Risk means the activity looks normal for the account.",
        ],
        "actions": [
            "How does suspicious login detection work?",
            "Can admins view risk alerts?",
        ],
        "suggestions": [
            "How does suspicious login detection work?",
            "Can admins view risk alerts?",
            "Why was my account locked?",
        ],
        "priority": 4,
    },
    {
        "category": "Monitoring",
        "title": "Dashboard and log tools",
        "tone": "info",
        "keywords": ["dashboard", "logs", "analytics", "report", "export", "audit"],
        "reply": (
            "Administrators can review user accounts, authentication history, and risk alerts from the "
            "dashboard and logs pages. Audit data can also be exported as CSV."
        ),
        "bullets": [
            "The dashboard shows users, recent alerts, and access metrics.",
            "The logs page tracks timestamps, IPs, devices, and risk labels.",
            "CSV export supports compliance reviews, reporting, and security analysis.",
        ],
        "actions": [
            "Can I export logs?",
            "What can admins do?",
        ],
        "suggestions": [
            "Can I export logs?",
            "What can admins do?",
            "Tell me about this project",
        ],
        "priority": 2,
    },
    {
        "category": "Status",
        "title": "Inactive account support",
        "tone": "warning",
        "keywords": ["inactive", "disabled", "suspended", "deactivated"],
        "reply": (
            "Inactive accounts cannot continue to the dashboard. An administrator needs to reactivate "
            "the account before the user can sign in again."
        ),
        "bullets": [
            "Admins can toggle account status from the dashboard.",
            "Inactive users are logged out immediately on the next protected request.",
            "Reactivation also clears lock state when the admin enables the account again.",
        ],
        "actions": [
            "What can admins do?",
            "Why was my account locked?",
        ],
        "suggestions": [
            "What can admins do?",
            "Why was my account locked?",
            "How do I log in?",
        ],
        "priority": 3,
    },
    {
        "category": "Project",
        "title": "SmartIAM project overview",
        "tone": "info",
        "keywords": ["platform", "features", "smartiam", "overview", "solution"],
        "reply": (
            "SmartIAM is an IAM platform that combines authentication, role-based access control, "
            "suspicious-login detection, audit logging, and admin analytics in one Flask app."
        ),
        "bullets": [
            "It is built with Flask, SQLite, Flask-Bcrypt, Flask-SQLAlchemy, and Matplotlib.",
            "The platform is designed for clear operational visibility and secure identity workflows.",
            "Security behavior is explained through logs, charts, and risk labels.",
        ],
        "actions": [
            "How does suspicious login detection work?",
            "What can admins do?",
        ],
        "suggestions": [
            "How does suspicious login detection work?",
            "What can admins do?",
            "How do I create an account?",
        ],
        "priority": 1,
    },
]


def chatbot_tokens(text):
    return {token for token in re.findall(r"[a-z0-9]+", text.lower()) if len(token) > 2}


for topic in CHATBOT_TOPICS:
    keyword_tokens = set()
    for keyword in topic["keywords"]:
        keyword_tokens.update(chatbot_tokens(keyword))
    topic["token_set"] = keyword_tokens


def build_chatbot_payload(
    reply,
    suggestions=None,
    *,
    title="SmartIAM Assistant",
    category="Assistant",
    tone="info",
    bullets=None,
    actions=None,
    highlights=None,
    status=None,
    provider="SmartIAM",
    model=None,
):
    return {
        "title": title,
        "category": category,
        "tone": tone,
        "reply": reply,
        "bullets": bullets or [],
        "actions": actions or [],
        "highlights": highlights or [],
        "status": status,
        "provider": provider,
        "model": model,
        "suggestions": (suggestions or CHATBOT_DEFAULT_SUGGESTIONS)[:3],
    }


def contains_any(text, phrases):
    return any(phrase in text for phrase in phrases)


def normalize_chatbot_history(history):
    cleaned = []

    if not isinstance(history, list):
        return cleaned

    for item in history[-CHATBOT_HISTORY_LIMIT:]:
        if not isinstance(item, dict):
            continue

        role = str(item.get("role") or "").strip().lower()
        message = str(item.get("message") or "").strip()
        category = str(item.get("category") or "").strip()

        if role not in {"user", "assistant"} or not message:
            continue

        cleaned.append(
            {
                "role": role,
                "message": message[:320],
                "category": category[:80],
            }
        )

    return cleaned


def get_chatbot_followup_category(history):
    for item in reversed(history):
        if item["role"] == "assistant" and item.get("category"):
            return item["category"]

    return None


def get_account_snapshot(username_hint):
    normalized_username = (username_hint or "").strip()
    if not normalized_username:
        return None

    user = User.query.filter_by(username=normalized_username).first()
    if not user:
        return {
            "username": normalized_username,
            "exists": False,
        }

    now = utc_now()
    last_day = now - timedelta(days=1)
    recent_logs = (
        LoginLog.query.filter_by(username=user.username)
        .order_by(LoginLog.created_at.desc())
        .limit(6)
        .all()
    )
    failed_24h = (
        LoginLog.query.filter(
            LoginLog.username == user.username,
            LoginLog.status == "failed",
            LoginLog.created_at >= last_day,
        ).count()
    )
    latest_high_risk = (
        LoginLog.query.filter(
            LoginLog.username == user.username,
            LoginLog.risk_level == "High Risk",
        )
        .order_by(LoginLog.created_at.desc())
        .first()
    )
    latest_log = recent_logs[0] if recent_logs else None

    return {
        "username": user.username,
        "exists": True,
        "role": user.role,
        "department": user.department,
        "is_active": user.is_active,
        "failed_attempts": user.failed_attempts or 0,
        "login_count": user.login_count or 0,
        "last_login_at": user.last_login_at,
        "locked_until": user.locked_until,
        "is_locked": bool(user.locked_until and user.locked_until > now),
        "recent_failed_24h": failed_24h,
        "latest_log": latest_log,
        "latest_high_risk": latest_high_risk,
    }


def build_snapshot_payload(snapshot):
    if not snapshot:
        return None

    username = snapshot["username"]

    if not snapshot["exists"]:
        return build_chatbot_payload(
            f"I could not find a SmartIAM account for '{username}'.",
            [
                "How do I create an account?",
                "How do I log in?",
                "What role should I choose?",
            ],
            title="No matching account found",
            category="Account lookup",
            tone="warning",
            bullets=[
                "Check the username spelling in the login form.",
                "If the account does not exist yet, create one from the register page.",
            ],
            actions=[
                "How do I create an account?",
                "How do I log in?",
            ],
            highlights=[
                f"Username: {username}",
                "Status: not found",
            ],
            status={
                "label": "Lookup result",
                "value": "No account matched that username",
                "tone": "warning",
            },
        )

    highlights = [
        f"User: {snapshot['username']}",
        f"Role: {snapshot['role'].title()}",
        f"Department: {snapshot['department']}",
    ]

    if snapshot["is_locked"]:
        if snapshot["recent_failed_24h"]:
            highlights.append(f"Failed attempts (24h): {snapshot['recent_failed_24h']}")

        return build_chatbot_payload(
            (
                f"The account '{snapshot['username']}' is currently locked. Wait until the lock window "
                "expires, then try the correct password or ask an administrator to review the account."
            ),
            [
                "How do I change my password?",
                "What does High Risk mean?",
                "What can admins do?",
            ],
            title="Account temporarily locked",
            category="Live account status",
            tone="warning",
            bullets=[
                f"Locked until: {format_datetime(snapshot['locked_until'])}",
                f"Current failed-attempt counter: {snapshot['failed_attempts']}",
                "A high-risk pattern or repeated failures can trigger the temporary lock.",
            ],
            actions=[
                "How do I change my password?",
                "What does High Risk mean?",
            ],
            highlights=highlights,
            status={
                "label": "Account",
                "value": f"Locked until {format_datetime(snapshot['locked_until'])}",
                "tone": "warning",
            },
        )

    if not snapshot["is_active"]:
        return build_chatbot_payload(
            (
                f"The account '{snapshot['username']}' is inactive. An administrator needs to reactivate "
                "it before the user can sign in again."
            ),
            [
                "What can admins do?",
                "How do I log in?",
                "How do I create an account?",
            ],
            title="Account is inactive",
            category="Live account status",
            tone="warning",
            bullets=[
                "Inactive accounts are blocked from protected pages.",
                "Admins can reactivate the account from the dashboard.",
            ],
            actions=[
                "What can admins do?",
                "How do I log in?",
            ],
            highlights=highlights,
            status={
                "label": "Account",
                "value": "Inactive and requires admin action",
                "tone": "warning",
            },
        )

    live_bullets = [
        f"Successful logins recorded: {snapshot['login_count']}",
        f"Recent failed attempts (24h): {snapshot['recent_failed_24h']}",
        (
            f"Last successful login: {format_datetime(snapshot['last_login_at'])}"
            if snapshot["last_login_at"]
            else "Last successful login: not recorded yet"
        ),
    ]

    if snapshot["latest_high_risk"]:
        live_bullets.append(
            f"Latest High Risk event: {format_datetime(snapshot['latest_high_risk'].created_at)}"
        )

    return build_chatbot_payload(
        (
            f"The account '{snapshot['username']}' looks available for sign-in right now."
            if snapshot["recent_failed_24h"] < 3
            else (
                f"The account '{snapshot['username']}' is active, but it has recent failed login activity "
                "that should be reviewed carefully."
            )
        ),
        [
            "How do I log in?",
            "What does High Risk mean?",
            "Can admins view risk alerts?",
        ],
        title=(
            "Account looks ready"
            if snapshot["recent_failed_24h"] < 3
            else "Recent failed sign-ins detected"
        ),
        category="Live account status",
        tone="warning" if snapshot["recent_failed_24h"] >= 3 else "info",
        bullets=live_bullets,
        actions=[
            "How do I log in?",
            "What does High Risk mean?",
        ],
        highlights=highlights,
        status={
            "label": "Account",
            "value": "Active" if snapshot["recent_failed_24h"] < 3 else "Active with recent failures",
            "tone": "warning" if snapshot["recent_failed_24h"] >= 3 else "info",
        },
    )


def score_chatbot_topic(normalized, tokens, topic, history):
    score = topic.get("priority", 0)
    for keyword in topic["keywords"]:
        if keyword in normalized:
            score += 12 if " " in keyword else 8

    token_overlap = len(tokens & topic["token_set"])
    score += token_overlap * 3

    followup_category = get_chatbot_followup_category(history)
    followup_tokens = {"why", "next", "fix", "solve", "details", "more", "how"}
    if followup_category == topic["category"] and tokens & followup_tokens:
        score += 7

    return score


def generate_local_chatbot_reply(message, context=None):
    normalized = re.sub(r"\s+", " ", message.lower()).strip()
    tokens = chatbot_tokens(normalized)
    context = context or {}
    history = normalize_chatbot_history(context.get("history"))
    username_hint = (context.get("username_hint") or "").strip()
    snapshot = get_account_snapshot(username_hint)

    if not normalized:
        return build_chatbot_payload(
            "Ask me about login, registration, password changes, risk alerts, or admin access.",
            title="Support ready",
            category="Welcome",
            bullets=[
                "Try a quick question about login, account lockouts, or admin tools.",
                "The assistant is tuned for fast SmartIAM support on this page.",
            ],
            actions=[
                "How do I log in?",
                "Why was my account locked?",
            ],
            highlights=([f"Username entered: {username_hint}"] if username_hint else []),
        )

    if normalized in {"hi", "hello", "hey"} or contains_any(
        normalized,
        ["good morning", "good afternoon", "good evening", "help", "support"],
    ):
        return build_chatbot_payload(
            (
                "I am the SmartIAM assistant. I can guide you through login issues, registration, "
                "lockouts, risk alerts, admin tools, and platform capabilities."
            ),
            [
                "How do I create an account?",
                "What can admins do?",
                "How does suspicious login detection work?",
            ],
            title="Instant SmartIAM support",
            category="Welcome",
            bullets=[
                "Use the quick replies for the fastest answers.",
                "The assistant is optimized for access and security questions on this page.",
            ],
            actions=[
                "How do I log in?",
                "How do I create an account?",
            ],
            highlights=([f"Username entered: {username_hint}"] if username_hint else []),
        )

    requested_live_check = bool(
        tokens
        & {"check", "diagnose", "status", "locked", "unlock", "account", "my", "login", "signin"}
    )

    if requested_live_check and username_hint and snapshot:
        snapshot_payload = build_snapshot_payload(snapshot)
        if snapshot_payload:
            return snapshot_payload

    if requested_live_check and not username_hint and contains_any(
        normalized,
        ["my account", "check account", "diagnose", "am i locked", "can i login", "account status"],
    ):
        return build_chatbot_payload(
            "Type a username in the login form first, then ask again and I can check the live account status.",
            [
                "How do I log in?",
                "How do I create an account?",
                "Why was my account locked?",
            ],
            title="Live account check needs a username",
            category="Account lookup",
            tone="info",
            bullets=[
                "The assistant can inspect whether the account is active, locked, or missing.",
                "Use the username field on the left, then ask the question again.",
            ],
            actions=[
                "Why was my account locked?",
                "How do I log in?",
            ],
            status={
                "label": "Live lookup",
                "value": "Waiting for a username",
                "tone": "info",
            },
        )

    best_topic = max(
        CHATBOT_TOPICS,
        key=lambda topic: score_chatbot_topic(normalized, tokens, topic, history),
    )
    best_score = score_chatbot_topic(normalized, tokens, best_topic, history)

    if best_score >= 8:
        highlights = [f"Username entered: {username_hint}"] if username_hint else []
        if snapshot and snapshot.get("exists"):
            highlights.extend(
                [
                    f"Role: {snapshot['role'].title()}",
                    (
                        f"Failed attempts (24h): {snapshot['recent_failed_24h']}"
                        if best_topic["category"] in {"Access", "Security", "Risk Engine", "Recovery"}
                        else f"Department: {snapshot['department']}"
                    ),
                ]
            )

        return build_chatbot_payload(
            best_topic["reply"],
            best_topic["suggestions"],
            title=best_topic["title"],
            category=best_topic["category"],
            tone=best_topic["tone"],
            bullets=best_topic["bullets"],
            actions=best_topic["actions"],
            highlights=highlights,
            status=(
                {
                    "label": "Account",
                    "value": "Locked" if snapshot["is_locked"] else "Active",
                    "tone": "warning" if snapshot["is_locked"] else "info",
                }
                if snapshot and snapshot.get("exists")
                else None
            ),
        )

    return build_chatbot_payload(
        (
            "I can help with login, registration, account locks, password changes, risk alerts, admin "
            "roles, logs, and SmartIAM project features."
        ),
        title="Try one of these support topics",
        category="Quick help",
        bullets=[
            "Ask a short question like login help, risk alerts, or account lock.",
            "Use the quick replies below for the fastest response.",
        ],
        actions=[
            "How do I log in?",
            "Tell me about this project",
        ],
    )


def openai_chatbot_ready():
    return bool(os.environ.get("OPENAI_API_KEY")) and OpenAI is not None


def get_openai_client():
    if not openai_chatbot_ready():
        return None

    return OpenAI()


def sanitize_chatbot_text(value, fallback, max_length):
    if not isinstance(value, str):
        return fallback

    cleaned = re.sub(r"\s+", " ", value).strip()
    return cleaned[:max_length] if cleaned else fallback


def sanitize_chatbot_list(value, fallback=None, max_items=3, item_length=120):
    if not isinstance(value, list):
        return list((fallback or [])[:max_items])

    cleaned = []
    for item in value:
        if not isinstance(item, str):
            continue

        text = re.sub(r"\s+", " ", item).strip()
        if text:
            cleaned.append(text[:item_length])

        if len(cleaned) >= max_items:
            break

    if cleaned:
        return cleaned

    return list((fallback or [])[:max_items])


def sanitize_chatbot_status(value, fallback=None):
    if not isinstance(value, dict):
        return fallback

    label = sanitize_chatbot_text(value.get("label"), "", 40)
    status_value = sanitize_chatbot_text(value.get("value"), "", 140)
    tone = value.get("tone") if value.get("tone") in {"info", "warning"} else None

    if not label or not status_value:
        return fallback

    return {
        "label": label,
        "value": status_value,
        "tone": tone or "info",
    }


def extract_json_object(text):
    if not isinstance(text, str):
        return None

    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.S)

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None

    try:
        return json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError:
        return None


def build_chatbot_openai_context(local_payload, context):
    snapshot = get_account_snapshot((context or {}).get("username_hint"))

    summary = {
        "project": "SmartIAM",
        "page": "login",
        "username_hint": (context or {}).get("username_hint") or "",
        "local_payload": {
            "title": local_payload["title"],
            "category": local_payload["category"],
            "tone": local_payload["tone"],
            "reply": local_payload["reply"],
            "bullets": local_payload["bullets"],
            "actions": local_payload["actions"],
            "highlights": local_payload["highlights"],
            "status": local_payload["status"],
        },
        "history": normalize_chatbot_history((context or {}).get("history")),
        "account_snapshot": None,
    }

    if snapshot:
        summary["account_snapshot"] = {
            "username": snapshot["username"],
            "exists": snapshot["exists"],
            "role": snapshot.get("role"),
            "department": snapshot.get("department"),
            "is_active": snapshot.get("is_active"),
            "failed_attempts": snapshot.get("failed_attempts"),
            "login_count": snapshot.get("login_count"),
            "recent_failed_24h": snapshot.get("recent_failed_24h"),
            "is_locked": snapshot.get("is_locked"),
            "locked_until": format_datetime(snapshot["locked_until"]) if snapshot.get("locked_until") else None,
            "last_login_at": format_datetime(snapshot["last_login_at"]) if snapshot.get("last_login_at") else None,
            "latest_high_risk": (
                format_datetime(snapshot["latest_high_risk"].created_at)
                if snapshot.get("latest_high_risk")
                else None
            ),
        }

    return summary


def build_chatbot_openai_input(message, local_payload, context):
    history = normalize_chatbot_history((context or {}).get("history"))
    context_summary = json.dumps(
        build_chatbot_openai_context(local_payload, context),
        ensure_ascii=True,
    )
    instructions = (
        "You are SmartIAM Assistant for a Flask login page. Answer only about SmartIAM login, "
        "registration, risk alerts, account state, dashboards, and project features. Never ask for "
        "passwords, API keys, or secrets. Use the provided account snapshot if present. Return only "
        "valid JSON with this exact shape: "
        '{"title":"...","category":"...","tone":"info or warning","reply":"...","bullets":["..."],'
        '"actions":["..."],"suggestions":["..."],"highlights":["..."],'
        '"status":{"label":"...","value":"...","tone":"info or warning"} or null}. '
        "Keep reply concise and professional. Use at most 3 bullets, 3 actions, 3 suggestions, and 4 highlights."
    )

    messages = [
        {
            "role": "developer",
            "content": [
                {
                    "type": "input_text",
                    "text": instructions,
                }
            ],
        },
        {
            "role": "developer",
            "content": [
                {
                    "type": "input_text",
                    "text": f"SmartIAM context:\n{context_summary}",
                }
            ],
        },
    ]

    for item in history[-CHATBOT_HISTORY_LIMIT:]:
        messages.append(
            {
                "role": item["role"],
                "content": [
                    {
                        "type": "input_text",
                        "text": item["message"],
                    }
                ],
            }
        )

    messages.append(
        {
            "role": "user",
            "content": [
                {
                    "type": "input_text",
                    "text": message,
                }
            ],
        }
    )

    return messages


def merge_openai_chatbot_payload(local_payload, ai_payload):
    if not isinstance(ai_payload, dict):
        return None

    merged = build_chatbot_payload(
        sanitize_chatbot_text(ai_payload.get("reply"), local_payload["reply"], 600),
        sanitize_chatbot_list(ai_payload.get("suggestions"), local_payload["suggestions"]),
        title=sanitize_chatbot_text(ai_payload.get("title"), local_payload["title"], 80),
        category=sanitize_chatbot_text(ai_payload.get("category"), local_payload["category"], 40),
        tone=ai_payload.get("tone") if ai_payload.get("tone") in {"info", "warning"} else local_payload["tone"],
        bullets=sanitize_chatbot_list(ai_payload.get("bullets"), local_payload["bullets"]),
        actions=sanitize_chatbot_list(ai_payload.get("actions"), local_payload["actions"]),
        highlights=sanitize_chatbot_list(ai_payload.get("highlights"), local_payload["highlights"], max_items=4),
        status=sanitize_chatbot_status(ai_payload.get("status"), local_payload["status"]),
        provider="OpenAI",
        model=CHATBOT_OPENAI_MODEL,
    )

    if "Provider: OpenAI" not in merged["highlights"]:
        merged["highlights"] = ["Provider: OpenAI", *merged["highlights"]][:4]

    if merged["model"]:
        model_highlight = f"Model: {merged['model']}"
        if model_highlight not in merged["highlights"] and len(merged["highlights"]) < 4:
            merged["highlights"].append(model_highlight)

    return merged


def generate_openai_chatbot_reply(message, context, local_payload):
    client = get_openai_client()
    if client is None:
        return None

    try:
        response = client.responses.create(
            model=CHATBOT_OPENAI_MODEL,
            input=build_chatbot_openai_input(message, local_payload, context),
        )
    except Exception:
        return None

    payload = extract_json_object(getattr(response, "output_text", ""))
    return merge_openai_chatbot_payload(local_payload, payload)


def generate_chatbot_reply(message, context=None):
    local_payload = generate_local_chatbot_reply(message, context)
    openai_payload = generate_openai_chatbot_reply(message, context or {}, local_payload)
    return openai_payload or local_payload


def utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


def ensure_schema():
    db.create_all()

    # The manual ALTER/BACKFILL statements below were written for the app's
    # legacy local SQLite database. On a fresh PostgreSQL deployment (Render),
    # SQLAlchemy already creates the full schema from the current models, so we
    # can skip the SQLite-specific migration path and avoid dialect-specific
    # startup failures.
    if db.engine.dialect.name != "sqlite":
        return

    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())

    alterations = {
        "user": [
            ('email', 'ALTER TABLE "user" ADD COLUMN email VARCHAR(120)'),
            ('department', 'ALTER TABLE "user" ADD COLUMN department VARCHAR(120)'),
            ('is_active', 'ALTER TABLE "user" ADD COLUMN is_active BOOLEAN DEFAULT 1'),
            ('failed_attempts', 'ALTER TABLE "user" ADD COLUMN failed_attempts INTEGER DEFAULT 0'),
            ('login_count', 'ALTER TABLE "user" ADD COLUMN login_count INTEGER DEFAULT 0'),
            ('created_at', 'ALTER TABLE "user" ADD COLUMN created_at DATETIME'),
            ('last_login_at', 'ALTER TABLE "user" ADD COLUMN last_login_at DATETIME'),
            ('locked_until', 'ALTER TABLE "user" ADD COLUMN locked_until DATETIME'),
        ],
        "login_log": [
            ('ip_address', 'ALTER TABLE "login_log" ADD COLUMN ip_address VARCHAR(64)'),
            ('user_agent', 'ALTER TABLE "login_log" ADD COLUMN user_agent VARCHAR(255)'),
            ('risk_score', 'ALTER TABLE "login_log" ADD COLUMN risk_score INTEGER DEFAULT 0'),
            (
                "risk_level",
                'ALTER TABLE "login_log" ADD COLUMN risk_level VARCHAR(50) DEFAULT \'Low Risk\'',
            ),
            ('reasons', 'ALTER TABLE "login_log" ADD COLUMN reasons TEXT'),
            ('created_at', 'ALTER TABLE "login_log" ADD COLUMN created_at DATETIME'),
        ],
    }

    for table_name, statements in alterations.items():
        if table_name not in existing_tables:
            continue

        current_columns = {column["name"] for column in inspector.get_columns(table_name)}
        for column_name, sql in statements:
            if column_name not in current_columns:
                db.session.execute(text(sql))

    db.session.commit()

    backfills = [
        'UPDATE "user" SET department = \'General\' WHERE department IS NULL OR TRIM(department) = \'\'',
        'UPDATE "user" SET is_active = 1 WHERE is_active IS NULL',
        'UPDATE "user" SET failed_attempts = 0 WHERE failed_attempts IS NULL',
        'UPDATE "user" SET login_count = 0 WHERE login_count IS NULL',
        'UPDATE "user" SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL',
        'UPDATE "login_log" SET risk_score = 0 WHERE risk_score IS NULL',
        'UPDATE "login_log" SET risk_level = \'Low Risk\' WHERE risk_level IS NULL OR TRIM(risk_level) = \'\'',
        'UPDATE "login_log" SET reasons = \'\' WHERE reasons IS NULL',
        'UPDATE "login_log" SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL',
    ]

    for sql in backfills:
        db.session.execute(text(sql))

    db.session.commit()


with app.app_context():
    ensure_schema()


@app.before_request
def load_user():
    user_id = session.get("user_id")
    g.current_user = db.session.get(User, user_id) if user_id else None


@app.context_processor
def inject_template_data():
    return {
        "project_name": "SmartIAM",
        "current_year": datetime.now().year,
    }


@app.template_filter("format_datetime")
def format_datetime(value):
    if not value:
        return "Never"

    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                value = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue

    return value.strftime("%d %b %Y, %I:%M %p") if hasattr(value, "strftime") else str(value)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not g.current_user:
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))

        if not g.current_user.is_active:
            session.clear()
            flash("Your account is inactive. Please contact the administrator.", "danger")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        if g.current_user.role != "admin":
            flash("Administrator access is required for this page.", "danger")
            return redirect(url_for("dashboard"))

        return view(*args, **kwargs)

    return wrapped_view


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded_for or request.remote_addr or "Unknown"


def get_user_agent():
    return (request.headers.get("User-Agent") or "Unknown device")[:255]


def build_risk_response(score, reasons):
    if score >= 60:
        status = "High Risk"
    elif score >= 30:
        status = "Medium Risk"
    else:
        status = "Low Risk"

    return {"status": status, "score": score, "reasons": reasons}


def detect_suspicious_login(
    username,
    account_role=None,
    ip_address=None,
    user_agent=None,
    pending_failed_increment=0,
    event_time=None,
):
    now = event_time or utc_now()
    last_hour = now - timedelta(hours=1)
    last_day = now - timedelta(days=1)

    failed_total = (
        LoginLog.query.filter_by(username=username, status="failed").count() + pending_failed_increment
    )
    recent_failed = (
        LoginLog.query.filter(
            LoginLog.username == username,
            LoginLog.status == "failed",
            LoginLog.created_at >= last_day,
        ).count()
        + pending_failed_increment
    )
    rapid_failures = (
        LoginLog.query.filter(
            LoginLog.username == username,
            LoginLog.status == "failed",
            LoginLog.created_at >= last_hour,
        ).count()
        + pending_failed_increment
    )

    ip_failures = 0
    if ip_address:
        ip_failures = (
            LoginLog.query.filter(
                LoginLog.ip_address == ip_address,
                LoginLog.status == "failed",
                LoginLog.created_at >= last_day,
            ).count()
            + pending_failed_increment
        )

    score = 0
    reasons = []

    if rapid_failures >= 3:
        score += 35
        reasons.append("Multiple failed attempts within one hour")

    if recent_failed >= 5:
        score += 25
        reasons.append("Possible brute-force pattern in the last 24 hours")

    if account_role == "admin" and recent_failed >= 2:
        score += 20
        reasons.append("Administrator account is being targeted")

    if ip_failures >= 4:
        score += 15
        reasons.append("Same IP address generated repeated failures")

    if user_agent:
        last_success = (
            LoginLog.query.filter_by(username=username, status="success")
            .order_by(LoginLog.created_at.desc())
            .first()
        )
        if last_success and last_success.user_agent and last_success.user_agent != user_agent:
            score += 10
            reasons.append("Login activity detected from a new device or browser")

    if event_time and (event_time.hour < 6 or event_time.hour >= 22):
        score += 10
        reasons.append("Attempt happened outside standard access hours")

    if failed_total >= 8:
        score += 15
        reasons.append("Long-running suspicious activity history detected")

    return build_risk_response(score, reasons)


def create_log_entry(username, status, risk_data, ip_address, user_agent, created_at):
    return LoginLog(
        username=username,
        status=status,
        ip_address=ip_address,
        user_agent=user_agent,
        risk_score=risk_data["score"],
        risk_level=risk_data["status"],
        reasons=" | ".join(risk_data["reasons"]),
        created_at=created_at,
    )


def build_login_chart(summary):
    categories = ["Success", "Failed", "Medium Risk", "High Risk"]
    values = [
        summary["success_count"],
        summary["failed_count"],
        summary["medium_risk_count"],
        summary["high_risk_count"],
    ]
    colors = ["#22c55e", "#ef4444", "#f59e0b", "#7c3aed"]

    fig, ax = plt.subplots(figsize=(8, 4.2))
    bars = ax.bar(categories, values, color=colors, width=0.58)
    ax.set_facecolor("#f8fafc")
    fig.patch.set_facecolor("#f8fafc")
    ax.set_title("Authentication Event Summary", fontsize=14, weight="bold")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#94a3b8")
    ax.spines["bottom"].set_color("#94a3b8")
    ax.tick_params(axis="x", labelsize=10)
    ax.tick_params(axis="y", labelsize=10)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            str(value),
            ha="center",
            va="bottom",
            fontsize=10,
            color="#0f172a",
        )

    img = io.BytesIO()
    plt.tight_layout()
    plt.savefig(img, format="png", bbox_inches="tight")
    plt.close(fig)
    img.seek(0)
    return base64.b64encode(img.getvalue()).decode("utf-8")


def get_dashboard_metrics(user):
    today_start = utc_now() - timedelta(days=1)

    if user.role == "admin":
        return {
            "primary": [
                {"label": "Total Users", "value": User.query.count()},
                {"label": "Active Accounts", "value": User.query.filter_by(is_active=True).count()},
                {
                    "label": "Failed Attempts (24h)",
                    "value": LoginLog.query.filter(
                        LoginLog.status == "failed",
                        LoginLog.created_at >= today_start,
                    ).count(),
                },
                {
                    "label": "High Risk Events",
                    "value": LoginLog.query.filter(LoginLog.risk_level == "High Risk").count(),
                },
            ],
            "recent_alerts": (
                LoginLog.query.filter(LoginLog.risk_level != "Low Risk")
                .order_by(LoginLog.created_at.desc())
                .limit(5)
                .all()
            ),
        }

    user_logs = (
        LoginLog.query.filter_by(username=user.username)
        .order_by(LoginLog.created_at.desc())
        .limit(10)
        .all()
    )
    success_count = sum(1 for log in user_logs if log.status == "success")
    failed_count = sum(1 for log in user_logs if log.status == "failed")

    return {
        "primary": [
            {"label": "Successful Logins", "value": user.login_count or 0},
            {"label": "Recent Failures", "value": failed_count},
            {"label": "Department", "value": user.department},
            {
                "label": "Last Login",
                "value": format_datetime(user.last_login_at) if user.last_login_at else "First login pending",
            },
        ],
        "recent_alerts": [log for log in user_logs if log.risk_level != "Low Risk"][:5],
    }


@app.route("/")
def home():
    return redirect(url_for("dashboard" if g.current_user else "login"))


@app.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.current_user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        department = request.form.get("department", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip().lower()

        if not all([username, email, department, password, role]):
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return redirect(url_for("register"))

        if role not in ["admin", "user"]:
            flash("Please choose a valid role.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose another one.", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists in the system.", "warning")
            return redirect(url_for("register"))

        user = User(
            username=username,
            email=email,
            department=department,
            password=bcrypt.generate_password_hash(password).decode("utf-8"),
            role=role,
            created_at=utc_now(),
        )

        db.session.add(user)
        db.session.commit()

        flash("Registration successful. You can now login to SmartIAM.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.current_user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        now = utc_now()
        ip_address = get_client_ip()
        user_agent = get_user_agent()

        if user and not user.is_active:
            flash("This account is inactive. Please contact the administrator.", "danger")
            return redirect(url_for("login"))

        if user and user.locked_until and user.locked_until > now:
            risk_data = build_risk_response(
                90,
                ["Login attempted while the account is temporarily locked"],
            )
            db.session.add(create_log_entry(username, "failed", risk_data, ip_address, user_agent, now))
            db.session.commit()

            flash(
                f"Account locked due to repeated failures. Try again after {format_datetime(user.locked_until)}.",
                "danger",
            )
            return redirect(url_for("login"))

        if user and bcrypt.check_password_hash(user.password, password):
            risk_data = detect_suspicious_login(
                username,
                account_role=user.role,
                ip_address=ip_address,
                user_agent=user_agent,
                event_time=now,
            )

            user.failed_attempts = 0
            user.locked_until = None
            user.last_login_at = now
            user.login_count = (user.login_count or 0) + 1

            db.session.add(create_log_entry(username, "success", risk_data, ip_address, user_agent, now))
            db.session.commit()

            session["user_id"] = user.id
            session["role"] = user.role

            if risk_data["status"] == "Low Risk":
                flash("Login successful. Access granted.", "success")
            else:
                flash(
                    f"Login successful, but the system flagged this session as {risk_data['status'].lower()}.",
                    "warning",
                )

            return redirect(url_for("dashboard"))

        risk_data = detect_suspicious_login(
            username,
            account_role=user.role if user else None,
            ip_address=ip_address,
            user_agent=user_agent,
            pending_failed_increment=1,
            event_time=now,
        )

        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5 or risk_data["status"] == "High Risk":
                user.locked_until = now + timedelta(minutes=15)
                risk_data = build_risk_response(
                    max(risk_data["score"], 80),
                    risk_data["reasons"] + ["Account locked for 15 minutes"],
                )

        db.session.add(create_log_entry(username, "failed", risk_data, ip_address, user_agent, now))
        db.session.commit()

        if risk_data["status"] == "High Risk":
            flash(
                "High-risk login pattern detected. The attempt has been recorded and the account may be locked.",
                "danger",
            )
        elif risk_data["status"] == "Medium Risk":
            flash("Suspicious login activity detected. Please verify your credentials carefully.", "warning")
        else:
            flash("Invalid credentials.", "danger")

        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/chatbot/respond", methods=["POST"])
def chatbot_respond():
    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "").strip()
    context = {
        "username_hint": (payload.get("usernameHint") or "").strip(),
        "history": payload.get("history") or [],
        "ip_address": get_client_ip(),
    }

    if not message:
        return (
            jsonify(
                build_chatbot_payload(
                    "Please type a question so I can help you in real time.",
                )
            ),
            400,
        )

    return jsonify(generate_chatbot_reply(message, context))


@app.route("/dashboard")
@login_required
def dashboard():
    security_posture = detect_suspicious_login(
        g.current_user.username,
        account_role=g.current_user.role,
    )
    recent_logs = (
        LoginLog.query.filter_by(username=g.current_user.username)
        .order_by(LoginLog.created_at.desc())
        .limit(6)
        .all()
    )
    users = User.query.order_by(User.created_at.desc()).all() if g.current_user.role == "admin" else None
    dashboard_metrics = get_dashboard_metrics(g.current_user)

    return render_template(
        "dashboard.html",
        user=g.current_user,
        role=g.current_user.role,
        users=users,
        ai_result=security_posture,
        dashboard_metrics=dashboard_metrics,
        recent_logs=recent_logs,
    )


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=g.current_user)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not all([current_password, new_password, confirm_password]):
            flash("Please complete all password fields.", "danger")
            return redirect(url_for("change_password"))

        if not bcrypt.check_password_hash(g.current_user.password, current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        if len(new_password) < 8:
            flash("New password must be at least 8 characters long.", "danger")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("New password and confirm password do not match.", "danger")
            return redirect(url_for("change_password"))

        g.current_user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()

        flash("Password updated successfully.", "success")
        return redirect(url_for("profile"))

    return render_template("change_password.html")


@app.route("/toggle-status/<int:id>", methods=["POST"])
@admin_required
def toggle_user_status(id):
    target_user = db.session.get(User, id)

    if not target_user:
        flash("User not found.", "warning")
        return redirect(url_for("dashboard"))

    if target_user.id == g.current_user.id:
        flash("You cannot change the status of your own account while logged in.", "warning")
        return redirect(url_for("dashboard"))

    target_user.is_active = not target_user.is_active
    if target_user.is_active:
        target_user.failed_attempts = 0
        target_user.locked_until = None
        flash(f"{target_user.username} has been activated.", "success")
    else:
        flash(f"{target_user.username} has been suspended.", "warning")

    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/delete/<int:id>", methods=["POST"])
@admin_required
def delete_user(id):
    target_user = db.session.get(User, id)

    if not target_user:
        flash("User not found.", "warning")
        return redirect(url_for("dashboard"))

    if target_user.id == g.current_user.id:
        flash("You cannot delete your own account while logged in.", "warning")
        return redirect(url_for("dashboard"))

    db.session.delete(target_user)
    db.session.commit()

    flash("User deleted successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logs")
@admin_required
def logs():
    log_entries = LoginLog.query.order_by(LoginLog.created_at.desc()).all()

    summary = {
        "success_count": sum(1 for log in log_entries if log.status == "success"),
        "failed_count": sum(1 for log in log_entries if log.status == "failed"),
        "medium_risk_count": sum(1 for log in log_entries if log.risk_level == "Medium Risk"),
        "high_risk_count": sum(1 for log in log_entries if log.risk_level == "High Risk"),
    }
    summary["total_events"] = len(log_entries)

    chart = build_login_chart(summary)

    return render_template("logs.html", logs=log_entries, chart=chart, summary=summary)


@app.route("/export-logs")
@admin_required
def export_logs():
    log_entries = LoginLog.query.order_by(LoginLog.created_at.desc()).all()

    def generate():
        yield "ID,Username,Status,Risk Level,Risk Score,IP Address,User Agent,Created At,Reasons\n"
        for log in log_entries:
            safe_user_agent = (log.user_agent or "").replace(",", " ")
            safe_reasons = (log.reasons or "").replace(",", " ")
            yield (
                f"{log.id},{log.username},{log.status},{log.risk_level},{log.risk_score},"
                f"{log.ip_address or 'Unknown'},{safe_user_agent},{format_datetime(log.created_at)},{safe_reasons}\n"
            )

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=smartiam_logs.csv"},
    )


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )
