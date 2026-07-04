# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the app

There are two virtual environments: `venv/` (Python 3.10) and `.venv/` (Python 3.12). The `.venv` is preferred for new work.

```powershell
# Activate venv (PowerShell)
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Initialize the database (first run only)
python -m flask --app server/server.py init-db

# Run the dev server
python server/server.py
# or
python -m flask --app server/server.py run --host=0.0.0.0 --debug
```

The server listens on `0.0.0.0:5000` (LAN-accessible). Set `FLASK_DEBUG=1` in environment for debug/reloader mode. A `.env` file (via python-dotenv) can set `SECRET_KEY` and `DATABASE_URL`.

**Promote a user to admin:**
```powershell
python -m flask --app server/server.py promote-admin <username>
```

**First registered user** is automatically made admin (checked in `/register` route via `User.query.count() == 0`).

## Architecture

Everything important lives in two places: `server/server.py` (all routes + socket handlers) and `server/models/` (SQLAlchemy ORM).

```
IntraComms/
├── server/
│   ├── server.py          # Flask app factory, all routes, Socket.IO handlers
│   └── models/
│       ├── database.py    # Shared SQLAlchemy `db` instance
│       ├── user.py        # User model (roles: admin/user, public_key field)
│       ├── message.py     # Message model (direct + broadcast types)
│       └── file_record.py # FileRecord model (defined but NO upload routes yet)
├── templates/             # Jinja2 templates (base.html + 5 pages)
├── static/
│   ├── css/app.css        # Single stylesheet — all design tokens are CSS vars in :root
│   └── js/chat.js         # Raw Socket.IO EIO4 client (no socket.io.js library)
├── uploads/               # File upload target dir (exists, no routes yet)
├── intracomms.db          # SQLite database (created by init-db)
└── requirements.txt
```

## Request / WebSocket flow

**HTTP fallback:** `POST /messages` → `build_message()` → save → `emit_saved_message()` → redirect to dashboard.

**WebSocket (primary path):** Client sends `42["send_message", {receiver_id, content}]` → `handle_socket_message()` → `build_message()` → save → `emit_saved_message()`. The JS client in `chat.js` implements the raw EIO4 framing protocol manually (no `socket.io.js` dependency). Ping/pong: server sends `"2"`, client responds `"3"`. Socket.IO connect: server sends `"0"`, client responds `"40"`.

**Room strategy:** On connect, each user joins `user_{id}` and `"broadcast"`. Direct messages are emitted to `user_{sender_id}` and `user_{receiver_id}`; broadcast messages go to `"broadcast"` room.

## Chat UI architecture

The dashboard is a two-panel layout: `.conversation-rail` (sidebar) + `.chat-panel`.

- Conversation switching is client-side only — all messages load on page load, JS hides/shows by filtering `data-message-type`, `data-sender-id`, `data-receiver-id` attributes.
- The hidden `<input id="receiver_id">` tracks the active conversation. Clicking a `.conversation-row` calls `setActiveChat()` which updates this value.
- Avatar colors cycle through 8 CSS classes (`avatar-c0`…`avatar-c7`) keyed by `userId % 8` in JS and `loop.index0 % 8` in Jinja.
- The `#preview-{chatId}` and `#preview-time-{chatId}` elements in the sidebar are populated by `initPreviews()` on load and `updatePreview()` on new messages.

## Theming

All colors are CSS custom properties in `:root` in `app.css`. The layout uses a dark navy navbar (`--nav-bg: #0f172a`) with a light body. Message area background is `#e8eff9`. Incoming bubbles are white (`--bubble-in: #ffffff`), outgoing are light blue (`--bubble-out: #dbeafe`).

## What is NOT yet implemented

- **File upload/download** — `FileRecord` model is fully defined with encryption fields, `uploads/` directory exists, `MAX_CONTENT_LENGTH` is configured, but there are zero HTTP routes for upload or download in `server.py`.
- **RSA/AES encryption** — `server/crypto/` is an empty stub directory. Currently all messages are stored with `aes_key_encrypted="plain-text-prototype"` and `iv="plain-text-prototype"`. The `cryptography==44.0.3` package is installed and ready to use.
- **`server/routes/` and `server/sockets/`** — empty stub directories; everything is inline in `server.py`.
