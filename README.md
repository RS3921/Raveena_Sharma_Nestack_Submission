# Secure Records API

A small multi-user API for account registration, sign-in, and private records. Users can read their own records; server-created admins can read any record. The project uses Flask and SQLite, with custom password, session, and access-control logic. It does not use an authentication library.

## Requirements

- Python 3.10 or newer
- Windows, macOS, or Linux

## Setup and run

Run these commands from the project directory.

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe manage.py gen-env
.\.venv\Scripts\python.exe run.py
```

If `.env` already exists, skip `manage.py gen-env`; it will not overwrite the existing pepper. Keep the server window open and visit <http://127.0.0.1:5000/>. The root page is an optional API walkthrough.

Alternatively, after setup, start the server by running `run_api.bat`.

### macOS or Linux

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python manage.py gen-env
python run.py
```

If `.env` already exists, skip `manage.py gen-env`. The server listens on `127.0.0.1:5000` by default. Set `HOST` or `PORT` before starting `run.py` to change the bind address or port.

## Configuration

`manage.py gen-env` creates a random `SERVER_PEPPER` and sets `DATABASE_PATH=records.db`. The application refuses to start if the pepper is missing or shorter than 32 bytes. Environment variables take precedence over values in `.env`.

`.env` and SQLite database files are ignored by Git. Do not commit the pepper or database.

## API

All request bodies must be JSON objects. Errors use this shape:

```json
{"error": "error_code", "message": "Description"}
```

| Method | Endpoint | Authentication | Success | Common errors |
|---|---|---|---|---|
| `POST` | `/register` | None | `201`; creates a `user` account | `400` invalid input, `403` privilege field, `409` username taken |
| `POST` | `/login` | None | `200`; returns a bearer token | `400` invalid input, `401` invalid credentials, `429` locked account |
| `POST` | `/records` | Bearer token | `201`; returns the new record ID | `400` invalid input, `401` missing or invalid token, `403` privilege field |
| `GET` | `/records/<id>` | Bearer token | `200`; returns an owned record or any record for an admin | `401` missing or invalid token, `404` missing or not owned |
| `POST` | `/logout` | Bearer token | `204`; revokes the session | `401` missing or invalid token |

The registration body is `{"username": "alice", "password": "..."}`. Record creation uses `{"title": "...", "body": "..."}`. Registration usernames are normalized to lowercase and limited to 3–32 letters, digits, `_`, `.`, or `-`; registration passwords must be 12–128 characters. Titles allow 1–200 characters and bodies 1–10,000 characters. The record owner is taken from the authenticated session, never from the request body.

### Try the API in PowerShell

With the server running, use another PowerShell window:

```powershell
$base = "http://127.0.0.1:5000"
$password = "replace-this-with-a-private-passphrase"
$account = @{ username = "alice"; password = $password } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$base/register" -ContentType "application/json" -Body $account

$login = Invoke-RestMethod -Method Post -Uri "$base/login" -ContentType "application/json" -Body $account
$headers = @{ Authorization = "Bearer $($login.token)" }

$recordBody = @{ title = "Private note"; body = "Only its owner or an admin can read this." } | ConvertTo-Json
$record = Invoke-RestMethod -Method Post -Uri "$base/records" -Headers $headers -ContentType "application/json" -Body $recordBody
Invoke-RestMethod -Method Get -Uri "$base/records/$($record.id)" -Headers $headers
```

The sample username can only be registered once in a given database. Choose a different username if it is already taken.

## Security design

### Passwords

Passwords are stored as salted `scrypt` hashes (`N=2^15`, `r=8`, `p=3`) with a fresh 16-byte random salt per account. Before hashing, the password is keyed with an application pepper from `SERVER_PEPPER`; the pepper is kept outside the database. Verification uses a constant-time comparison. Unknown usernames use a dummy hash so their login path performs password work too.

### Sessions

Login returns a cryptographically random, opaque bearer token. SQLite stores only its SHA-256 hash and expiry time. Every protected request hashes the supplied token and looks up an unexpired session joined to its user. The user’s current role is read from the database on each request. Logout deletes the session, immediately revoking the token.

### Record authorization and roles

Every record read requires a valid session and then checks ownership. Admin access is an explicit server-side exception to the ownership rule. Missing records and records owned by someone else return the same `404` response. New records always take their owner ID from the session.

Registration always creates a `user`. Requests containing role or privilege fields are rejected with `403`; there is no role-editing HTTP endpoint. Operators assign admin roles through `manage.py create-admin` or `manage.py set-role`. The database also constrains roles to `user` or `admin`.

### Validation, SQL, and login abuse

The API checks JSON shape, field names, types, lengths, and a 16 KB request-body limit. SQL statements use bound parameters. Malformed and oversized input returns a JSON `400` response.

Failed logins are limited per account name. Five failures within 15 minutes lock the account for 15 minutes; further attempts receive `429` and a `Retry-After` header. Attempts are reserved in a SQLite write transaction before password verification so concurrent guesses cannot bypass the limit.

### If the user table is exposed

A read-only copy can reveal usernames, user IDs, roles, creation times, and password hashes. It does not contain plaintext passwords or usable session tokens. The unique salts and slow hash make password guessing costly; the separate pepper prevents database-only offline guesses. Record contents are not encrypted at rest, and an attacker with write access to the database can alter data or roles. Protect the database and back up the pepper separately.

## Create an admin

This is an operator-only step. With `.env` configured, run the command from the project directory; it prompts for the password:

```powershell
.\.venv\Scripts\python.exe manage.py create-admin root
```

On macOS or Linux, use `python manage.py create-admin root` from the activated virtual environment.

## Tests

Install the development dependencies as shown above, then run:

```bash
python -m pytest -q
```

The suite covers passwords, session handling, record access, role escalation, login lockout, input validation, SQL injection, and configuration.

## Project structure

```text
app/
  access.py       record authorization policy
  auth.py         registration, login, sessions, and lockout
  config.py       environment-based configuration
  routes.py       HTTP endpoints and error responses
  security.py     password hashes and session tokens
  storage.py      SQLite schema and parameterized queries
  validation.py   request parsing and input validation
  templates/      API walkthrough page
  static/         page behavior and styles
manage.py         operator commands for pepper and admin setup
run.py            Flask development server
run_api.bat       Windows launcher
tests/            automated security and behavior tests
```

## Deployment note

`run.py` starts Flask's development server for local use. For deployment, use a production WSGI server and terminate TLS at a trusted reverse proxy.
