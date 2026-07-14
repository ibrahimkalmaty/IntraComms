# IntraComms — Setup & Run

This README describes how to set up and run the IntraComms Flask application on Windows and Linux.

## Prerequisites

- Python 3.10+ (project has two virtualenvs: `venv/` for Python 3.10 and `.venv/` for Python 3.12; `.venv` is preferred for new work)
- Git (optional)
- `pip` (comes with Python)

## Install dependencies (both platforms)

From the repository root, install requirements into a virtual environment.

### Linux / macOS (bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

Notes:
- Some systems may use `python` instead of `python3`.
- A project `venv/` may already exist; `.venv/` is the preferred environment for new work.

## Optional: create a `.env` file

Create a `.env` file in the repo root to set `SECRET_KEY` and `DATABASE_URL` (python-dotenv is used):

```
SECRET_KEY=your_secret_here
DATABASE_URL=sqlite:///intracomms.db
```

If you omit `DATABASE_URL` the app will default to a local SQLite database.

## Initialize the database

Run the Flask helper to initialize the database (first run only):

```bash
# from activated virtualenv
python -m flask --app server/server.py init-db
```

## Run the development server

You can run the app directly or via `flask run`.

Direct (recommended for quick run):

```bash
python server/server.py
```

Using Flask CLI with reloader (development):

```bash
export FLASK_DEBUG=1       # Linux/macOS
setx FLASK_DEBUG 1         # Windows (persisted)
python -m flask --app server/server.py run --host=0.0.0.0 --debug
```

The server listens on port `5000` by default.

## Promote a user to admin

To promote an existing user to admin (PowerShell examples shown in CLAUDE.md):

```bash
# Replace <username> with the target username
python -m flask --app server/server.py promote-admin <username>
```

Notes:
- The first registered user is automatically made admin by the app logic.
- If you need to create an admin quickly, register a new user via the web UI and then promote if needed.

## Development notes

- Architecture and helpful commands are documented in `CLAUDE.md`.
- File upload/download routes are not yet implemented; `server/models/file_record.py` and `uploads/` exist as stubs.
- Encryption utilities are currently stubs in `server/crypto/`; messages are stored with placeholder AES fields.

## Troubleshooting

- If packages fail to install, ensure your virtualenv is activated and that you are using a supported Python version.
- If Flask cannot find the app, ensure `--app server/server.py` is passed to `flask`.
- If database commands fail, remove or rename `intracomms.db` and rerun `init-db` to recreate it.

## Useful commands recap

Linux/macOS (bash):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m flask --app server/server.py init-db
python server/server.py
```

Windows (PowerShell):

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python -m flask --app server/server.py init-db
python server/server.py
```

---

If you'd like, I can also add a `run.ps1` and `run.sh` helper script, or update `requirements.txt` with pinned versions. Want me to add those?
