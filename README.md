# Multi Property Booking System

client URL: https://github.com/Benjamin0-1/calendar-app-client-flask

## Overview

The Property Booking System is a web application designed to streamline property management and booking. This repository is the Flask REST API behind it: user authentication, properties, bookings, and an archive of deleted bookings.

## Features

- **JWT Authentication**: Uses JSON Web Tokens (JWTs) for secure user authentication, with refresh tokens to obtain new access tokens.
- **Google Login**: Sign in with Google through Firebase.
- **Brute Force Protection**: Locks an account's logins for 5 minutes after 5 failed attempts.
- **Email Confirmation**: Requires email verification upon user registration, via a link sent by email.
- **Password Reset**: One-time codes sent by email.
- **Property Management**: Allows users to create, view and delete multiple properties.
- **Booking System**: Enables users to book dates for their properties, with validations that prevent past or double bookings, plus filtering, sorting and pagination.
- **Deleted Bookings Archive**: Deleted bookings (and the bookings of deleted properties) are archived and can be reviewed or purged.
- **Booking Reminders**: A background job emails users about the bookings they have today.

## Technologies Used

- **Backend**: Python with Flask and SQLAlchemy
- **Validation**: Marshmallow
- **Database**: PostgreSQL
- **Authentication**: JWT tokens for secure user access, Firebase for Google login
- **Frontend**: React.js with MUI5

## Project Structure

```
run.py                      # entry point: creates the app and starts the scheduler
app/
  __init__.py               # create_app() factory
  config.py                 # settings read from environment variables
  extensions.py             # db, mail, oauth, limiter
  errors.py                 # APIError and the handler that turns it into a JSON response
  blueprints/               # controllers: validate the request, call a service, respond
    auth/  bookings/  main/
  schemas/                  # Marshmallow request validation and response serialization
  services/                 # business logic (auth, account, booking, property, email, scheduler)
  middleware/               # email-confirmed check run before auth and bookings routes
  models/                   # SQLAlchemy models
  templates/email/          # Jinja templates for outgoing emails
  utils/
instance/                   # Firebase service account config (firebase_config.json)
migrations/                 # Alembic migrations
scripts/                    # reset_db.py, run_migrations.py
tests/                      # pytest suite
```

### How a request flows

1. A route in `app/blueprints/` validates the request with a schema from `app/schemas/`.
2. It calls a function in `app/services/`, which holds the business logic.
3. Services raise `APIError(body, status)` for expected failures; `app/errors.py` turns it into the JSON response.

Validation failures return the same error bodies and status codes as the checks they replaced (for example `{"missingData": true}` with 400 on signup), so the frontend sees a stable API.

## Setup Instructions

Requires Python 3.12 and a running PostgreSQL server.

```bash
git clone https://github.com/Benjamin0-1/calendar-app-server-flask.git
cd calendar-app-server-flask
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Place the Firebase service account file at `instance/firebase_config.json`, then set these environment variables (for example in `.env`):

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection URL |
| `SECRET_KEY`, `JWT_SECRET_KEY` | Flask and JWT signing keys |
| `JWT_ACCESS_TOKEN_EXPIRES`, `JWT_REFRESH_TOKEN_EXPIRES` | Token lifetimes, in minutes and days |
| `MAIL_USERNAME`, `MAIL_PASSWORD`, `EMAIL_SENDER` | Gmail SMTP account used to send emails |
| `FRONTEND_URL` | Frontend base URL, used in email links and redirects |
| `ORIGIN` | Extra allowed CORS origin (`http://localhost:5173` and `http://127.0.0.1:5173` are always allowed) |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google OAuth credentials |

`run.py` does not read `.env` by itself; export it into your shell first:

```bash
set -a; source .env; set +a
```

### Run

```bash
python scripts/run_migrations.py   # create or upgrade the database schema
python run.py                       # serves on http://127.0.0.1:5000
```

## Tests

```bash
pip install pytest pytest-mock
pytest tests
```

The tests use an in-memory SQLite database, so no PostgreSQL server is needed. `tests/test_api_contract.py` replays a scripted session against every endpoint and compares each response, and every email sent, with `tests/snapshots/api_contract.json`. After an intentional API change, re-record it with:

```bash
UPDATE_SNAPSHOT=1 pytest tests/test_api_contract.py
```
