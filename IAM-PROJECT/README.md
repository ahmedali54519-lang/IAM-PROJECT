# SmartIAM

SmartIAM is an **AI-driven Identity and Access Management platform** that combines secure authentication, role-based access control, suspicious login detection, audit logging, and admin analytics in a single Flask application.

## Abstract

Modern organizations need to control who can access systems, how they authenticate, and how suspicious access attempts are detected. SmartIAM addresses this problem by combining user registration, secure password hashing, role-based access control, account lifecycle management, and a lightweight AI-inspired risk engine that flags suspicious login behavior based on failed attempts, IP repetition, device changes, and abnormal access time.

## Core Features

- Secure user registration and login using hashed passwords
- Role-based access control for `admin` and `user`
- Department-aware identity records
- Suspicious login scoring with `Low Risk`, `Medium Risk`, and `High Risk` labels
- Temporary account lock after repeated failed login attempts
- Admin dashboard for user monitoring and account suspension
- Detailed authentication logs with IP address, device info, timestamp, and reasons
- CSV export for audit and report generation
- Profile management and password change workflow

## Platform Modules

1. **User Management Module**
   Handles registration, profile data, roles, and department mapping.

2. **Authentication Module**
   Validates login credentials, stores sessions, and protects password updates.

3. **Risk Detection Module**
   Detects suspicious behavior using rule-based risk scoring over login events.

4. **Audit and Reporting Module**
   Stores activity logs, generates analytics, and supports CSV export.

5. **Admin Control Module**
   Lets administrators suspend, activate, and delete user accounts.

## Technology Stack

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Bcrypt
- SQLite
- HTML, CSS, Jinja2
- Matplotlib

## Application Structure

```text
IAM-PROJECT/
|-- app.py
|-- models.py
|-- requirements.txt
|-- static/
|   `-- app.css
|-- templates/
|   |-- base.html
|   |-- login.html
|   |-- register.html
|   |-- dashboard.html
|   |-- profile.html
|   |-- change_password.html
|   `-- logs.html
`-- instance/
    `-- database.db
```

## How To Run

1. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

2. Activate the environment:

   Windows:

   ```bash
   .venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the application:

   ```bash
   python app.py
   ```

5. Open the browser:

   ```text
   http://127.0.0.1:5000
   ```

## OpenAI Chatbot Setup

The login-page assistant can use OpenAI for more advanced responses while keeping your API key on the Flask server.

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Set your API key as an environment variable.

   Windows PowerShell:

   ```powershell
   $env:OPENAI_API_KEY="your_api_key_here"
   ```

3. Optional: choose a different model.

   ```powershell
   $env:OPENAI_CHATBOT_MODEL="gpt-5.4-mini"
   ```

4. Run the Flask app normally.

If `OPENAI_API_KEY` is missing, SmartIAM falls back to the built-in local chatbot logic automatically.

## Public Deployment on Render

This repository is prepared for public deployment on Render using the included [`render.yaml`](./render.yaml) Blueprint.

### What changed for deployment

- The app now supports `DATABASE_URL` for production databases
- Gunicorn is included as the production web server
- PostgreSQL is supported through `psycopg`
- A `/healthz` endpoint is available for Render health checks
- Secure session cookies can be enabled with `SESSION_COOKIE_SECURE=1`

### Deploy steps

1. Push this project to GitHub.
2. Sign in to Render and choose **New +** -> **Blueprint**.
3. Connect the GitHub repository that contains this project.
4. Render will detect `render.yaml` and propose:
   - one Python web service
   - one PostgreSQL database
5. Set `OPENAI_API_KEY` during setup if you want the chatbot to use OpenAI in production.
6. Deploy the Blueprint.

### Important production notes

- Public deployments should use PostgreSQL instead of local SQLite
- The included Blueprint automatically wires `DATABASE_URL` from Render Postgres
- `SECRET_KEY` is generated automatically by Render during Blueprint creation
- If you do not set `OPENAI_API_KEY`, the chatbot still works with the built-in local fallback logic

## Operational Highlights

- Identity and access controls for admin and user roles
- Suspicious login detection based on device, IP, timing, and failure patterns
- Audit-ready logs with timestamps, risk labels, and export support
- Administrative controls for account lifecycle management
- Optional OpenAI-powered login assistant for faster support workflows

## Roadmap

- Multi-factor authentication
- Email or SMS OTP verification
- Machine learning model for anomaly detection
- Face recognition or biometric login
- REST API integration for enterprise systems
- Cloud deployment and centralized admin monitoring

## Outcome

SmartIAM provides a compact but credible IAM platform experience that combines **security monitoring**, **identity operations**, **audit visibility**, and **AI-assisted support** in a practical real-world workflow.
