"""Generate IntraComms Architecture PDF using fpdf2."""
from fpdf import FPDF
from fpdf.enums import XPos, YPos

NAVY  = (15,  23,  42)
BLUE  = (30,  64, 175)
LIGHT = (219, 234, 254)
GRAY  = (100, 116, 139)
WHITE = (255, 255, 255)
RED   = (185,  28,  28)
GREEN = (21, 128,  36)


class PDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(20, 20, 20)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*GRAY)
        self.cell(0, 8, "IntraComms  -  Messaging & Security Architecture", align="L",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*GRAY)
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*GRAY)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    # -- primitives -----------------------------------------------------------

    def h1(self, text):
        self.ln(4)
        self.set_fill_color(*NAVY)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 9, f"  {text}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def h2(self, text):
        self.ln(3)
        self.set_text_color(*BLUE)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*BLUE)
        self.set_line_width(0.5)
        self.line(self.l_margin, self.get_y(), self.l_margin + 60, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def body(self, text, indent=0):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(0, 0, 0)
        x = self.l_margin + indent
        w = self.w - self.l_margin - self.r_margin - indent
        self.set_x(x)
        self.multi_cell(w, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def bullet(self, text, indent=4):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(0, 0, 0)
        w = self.w - self.l_margin - self.r_margin - indent - 5
        self.set_x(self.l_margin + indent)
        self.cell(5, 5.5, "-")
        self.multi_cell(w, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def code(self, text):
        self.set_fill_color(240, 244, 248)
        self.set_draw_color(200, 210, 220)
        self.set_line_width(0.3)
        self.set_font("Courier", "", 8.5)
        self.set_text_color(30, 30, 30)
        lines = text.strip().split("\n")
        w = self.w - self.l_margin - self.r_margin
        pad = 3
        # background rect
        total_h = len(lines) * 4.8 + pad * 2
        self.rect(self.l_margin, self.get_y(), w, total_h, style="DF")
        start_y = self.get_y() + pad
        for i, line in enumerate(lines):
            self.set_xy(self.l_margin + pad, start_y + i * 4.8)
            self.cell(w - pad * 2, 4.8, line)
        self.set_xy(self.l_margin, self.get_y() + total_h)
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def table(self, headers, rows, col_widths=None):
        w = self.w - self.l_margin - self.r_margin
        n = len(headers)
        if col_widths is None:
            col_widths = [w / n] * n

        # Header row
        self.set_fill_color(*NAVY)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 9)
        x = self.l_margin
        row_h = 7
        for i, h in enumerate(headers):
            self.set_xy(x, self.get_y())
            self.cell(col_widths[i], row_h, f"  {h}", fill=True, border=0)
            x += col_widths[i]
        self.ln(row_h)

        # Data rows
        self.set_font("Helvetica", "", 9)
        for ridx, row in enumerate(rows):
            # estimate row height (tallest cell)
            needed = row_h
            for ci, cell in enumerate(row):
                lines_needed = self.get_string_width(str(cell)) / (col_widths[ci] - 4) + 1
                needed = max(needed, int(lines_needed) * 5 + 2)

            fill = ridx % 2 == 1
            self.set_fill_color(*LIGHT)
            self.set_text_color(0, 0, 0)
            x = self.l_margin
            y = self.get_y()
            for ci, cell in enumerate(row):
                self.set_xy(x, y)
                self.multi_cell(col_widths[ci], needed, f"  {cell}",
                                fill=fill, border=0,
                                new_x=XPos.RIGHT, new_y=YPos.TOP)
                x += col_widths[ci]
            self.set_xy(self.l_margin, y + needed)
        self.ln(4)

    def badge(self, text, color):
        self.set_fill_color(*color)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 8)
        self.cell(self.get_string_width(text) + 6, 6, text, fill=True, border=0)
        self.set_text_color(0, 0, 0)

    def kv(self, key, val):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*BLUE)
        kw = self.get_string_width(key + ": ") + 1
        self.cell(kw, 5.5, key + ": ")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(0, 0, 0)
        self.multi_cell(
            self.w - self.l_margin - self.r_margin - kw, 5.5, val,
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )


# -----------------------------------------------------------------------------

def build():
    pdf = PDF()

    # -- Cover page ------------------------------------------------------------
    pdf.add_page()
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, pdf.h, style="F")

    pdf.set_y(55)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 14, "IntraComms", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 15)
    pdf.set_text_color(147, 197, 253)
    pdf.cell(0, 9, "Messaging & Security Protocol Architecture", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(10)
    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(1)
    pdf.line(40, pdf.get_y(), pdf.w - 40, pdf.get_y())
    pdf.ln(10)

    details = [
        ("Project", "LAN Offline Messaging & File Sharing System"),
        ("Author",  "Ibrahim Habib  -  Lincoln University College"),
        ("Stack",   "Flask / Socket.IO / Web Crypto API / AES-256-GCM"),
        ("Version", "2025  -  Final Year Project"),
    ]
    pdf.set_font("Helvetica", "", 11)
    for k, v in details:
        pdf.set_text_color(147, 197, 253)
        pdf.set_x(40)
        pdf.cell(35, 8, k + ":")
        pdf.set_text_color(*WHITE)
        pdf.cell(0, 8, v, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(15)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 130, 180)
    pdf.cell(0, 6, "CONFIDENTIAL  -  Internal use only", align="C")

    # -- Section 1: Overview ---------------------------------------------------
    pdf.add_page()
    pdf.h1("1. System Overview")
    pdf.body(
        "IntraComms is a LAN-only, offline-first group/direct messaging system. "
        "It has no cloud dependency  -  all traffic stays inside your local network. "
        "The server is a single Python process (server/server.py) built on Flask + "
        "Flask-SocketIO + eventlet. The client is a browser page with raw WebSocket "
        "handling and the Web Crypto API."
    )

    pdf.h2("Architecture Diagram")
    pdf.code(
        "Browser (A)                   Server (Flask/eventlet)           Browser (B)\n"
        "   |                                   |                               |\n"
        "   |--- WSS (EIO4) ------------------>|<--- WSS (EIO4) ---------------|\n"
        "   |--- HTTPS REST ------------------->|<--- HTTPS REST ----------------|\n"
        "   |                                   |                               |\n"
        "        TLS (self-signed cert, localhost + LAN IP in SAN)\n"
        "\n"
        "Key components:\n"
        "  server/server.py     All routes, WebSocket handlers, E2EE key endpoints\n"
        "  server/models/       SQLAlchemy ORM  (User, Message, FileRecord)\n"
        "  static/js/chat.js    EIO4 client, E2EE module, file upload\n"
        "  static/css/app.css   Single stylesheet  -  all tokens in :root\n"
        "  uploads/             Processed media files (unencrypted at rest)\n"
        "  intracomms.db        SQLite database"
    )

    pdf.h2("Technology Stack")
    pdf.table(
        ["Layer", "Technology"],
        [
            ["HTTP server",     "Flask 3.x + Werkzeug"],
            ["WebSocket",       "Flask-SocketIO + eventlet (EIO4 transport)"],
            ["Database",        "SQLite via SQLAlchemy ORM"],
            ["Auth",            "Flask-Login + Werkzeug PBKDF2-SHA-256"],
            ["TLS",             "Self-signed cert (cryptography lib or openssl CLI)"],
            ["E2EE (client)",   "Web Crypto API  -  ECDH P-256 + AES-256-GCM"],
            ["Media processing","Pillow (images) + FFmpeg (audio/video)"],
            ["Scheduling",      "APScheduler (stale upload cleanup)"],
        ],
        col_widths=[60, 110],
    )

    # -- Section 2: TLS --------------------------------------------------------
    pdf.h1("2. Transport Security (TLS / HTTPS)")

    pdf.h2("Certificate Generation")
    pdf.body(
        "At first startup, _ensure_ssl_cert() runs two fallback methods to produce "
        "cert.pem and key.pem in the project root. The cert includes a Subject "
        "Alternative Name (SAN) with localhost, 127.0.0.1, and the machine's LAN IP."
    )
    pdf.table(
        ["Method", "Library", "Key Type", "Validity"],
        [
            ["1 (primary)",  "cryptography Python package", "RSA-2048", "10 years"],
            ["2 (fallback)", "openssl CLI (MSYS2/Git Bash)", "RSA-2048", "10 years"],
        ],
        col_widths=[35, 70, 40, 25],
    )

    pdf.h2("Why TLS Is Required")
    pdf.body(
        "window.crypto.subtle (the Web Crypto API) is only available in a secure "
        "context  -  HTTPS or localhost. Any LAN client on http://192.168.x.x:5000 "
        "has crypto.subtle = undefined, which completely disables E2EE. HTTPS is "
        "not optional for multi-device use."
    )

    pdf.h2("localStorage Origin Isolation  -  Critical")
    pdf.body(
        "Chrome isolates localStorage by origin. http://host:5000 and "
        "https://host:5000 are completely separate namespaces. Switching protocols "
        "invalidates all stored private keys. If you change HTTP to HTTPS, delete "
        "intracomms.db and let all users re-register fresh keypairs."
    )

    # -- Section 3: Auth -------------------------------------------------------
    pdf.h1("3. Authentication & Session Management")
    pdf.table(
        ["Mechanism", "Detail"],
        [
            ["Password hashing",   "werkzeug PBKDF2-SHA-256 (generate_password_hash)"],
            ["Session cookie",     "Flask-Login signed cookie (SECRET_KEY from env)"],
            ["WebSocket auth",     "current_user.is_authenticated checked on every connect event"],
            ["First user",         "Automatically promoted to admin role"],
            ["Admin CLI",          "flask promote-admin <username>"],
            ["Account control",    "Admin can activate / deactivate / change role"],
        ],
        col_widths=[55, 115],
    )
    pdf.body(
        "All routes that serve data are decorated with @login_required. The "
        "WebSocket handle_connect handler rejects unauthenticated connections by "
        "returning False."
    )

    # -- Section 4: WebSocket --------------------------------------------------
    pdf.add_page()
    pdf.h1("4. Real-Time Transport (WebSocket / EIO4)")

    pdf.body(
        "The client implements the Engine.IO v4 protocol manually in chat.js. "
        "There is no socket.io.js library bundled  -  the framing is done in raw JS."
    )

    pdf.h2("Handshake Sequence")
    pdf.code(
        "Client                   Server\n"
        "  |-- WSS connect ------>|\n"
        "  |<-- '0' (EIO open) ---| Server sends EIO open packet\n"
        "  |-- '40' ------------->| Client sends Socket.IO connect\n"
        "  |<-- '40' -------------| Server confirms Socket.IO connected\n"
        "                           <- flushQueue() runs here (queued msgs sent)"
    )

    pdf.h2("Keep-Alive (Ping / Pong)")
    pdf.code(
        "Server --- '2' (ping) ---> Client\n"
        "Client <-- '3' (pong) ---  Server"
    )

    pdf.h2("Message Framing")
    pdf.body('All application messages use prefix "42" (Socket.IO event packet):')
    pdf.code(
        '42["message", {\n'
        '  "type": "send_message",\n'
        '  "payload": { "receiver_id": "5", "content": "<ciphertext>", ... },\n'
        '  "requestId": "abc123"\n'
        "}]"
    )

    pdf.h2("Room Strategy (Server-Side)")
    pdf.table(
        ["Room", "Members", "Used For"],
        [
            ["user_{id}",  "Each user on connect",  "Direct messages, presence events"],
            ["broadcast",  "All users on connect",   "Broadcast messages, presence broadcast"],
        ],
        col_widths=[35, 55, 80],
    )

    pdf.h2("Reconnect Strategy")
    pdf.body(
        "Exponential backoff: starts at 1 s, doubles on each failure, caps at 30 s. "
        "Messages sent while disconnected are buffered in messageQueue[] and "
        "flushed automatically after reconnect."
    )

    # -- Section 5: E2EE -------------------------------------------------------
    pdf.add_page()
    pdf.h1("5. End-to-End Encryption (E2EE) Protocol")

    pdf.h2("Algorithm Suite")
    pdf.table(
        ["Component", "Algorithm", "Notes"],
        [
            ["Identity keys",     "ECDH P-256",        "Persistent per-device, stored as JWK in localStorage"],
            ["Key agreement",     "ECIES (ephemeral DH)", "New ephemeral keypair per message, discarded after use"],
            ["Symmetric cipher",  "AES-256-GCM",       "12-byte random IV; provides confidentiality + integrity"],
            ["Key derivation",    "SubtleCrypto deriveKey(ECDH)", "One-step HKDF-like derivation"],
            ["PRNG",              "crypto.getRandomValues", "Browser CSPRNG; Math.random never used"],
        ],
        col_widths=[42, 50, 78],
    )

    pdf.h2("Key Lifecycle")
    pdf.code(
        "FIRST VISIT (new device or cleared localStorage)\n"
        "  crypto.subtle.generateKey(ECDH P-256)\n"
        "    |- privateKey --> persisted as JWK in localStorage['intracomms_priv_jwk_v1']\n"
        "    \\- publicKey  --> base64-SPKI --> POST /api/me/pubkey --> User.public_key in DB\n"
        "\n"
        "SUBSEQUENT VISITS (same device, same origin)\n"
        "  load JWK from localStorage\n"
        "    |- importKey --> _privateKey (non-extractable CryptoKey in memory)\n"
        "    \\- reconstruct publicKey --> re-POST /api/me/pubkey (idempotent on server)"
    )

    pdf.h2("Encryption Flow (Sender --> Recipient)")
    pdf.code(
        "1. Fetch recipient public key (base64-SPKI) from userPubkeys[] cache\n"
        "     If not cached --> GET /api/users/<id>/pubkey\n"
        "\n"
        "2. Generate ephemeral ECDH P-256 keypair -- discarded after this call\n"
        "\n"
        "3. DH(ephemeral_private, recipient_public) --> shared_secret_1\n"
        "   deriveKey(AES-256-GCM 256-bit) from shared_secret_1\n"
        "   iv_1 = crypto.getRandomValues(12 bytes)\n"
        "   ciphertext_for_recipient = AES-GCM-Encrypt(key_1, iv_1, plaintext)\n"
        "\n"
        "4. ALSO encrypt for own public key (so sender can read own messages):\n"
        "   Generate second ephemeral keypair\n"
        "   DH(ephemeral_private_2, sender_public) --> shared_secret_2\n"
        "   sender_copy = AES-GCM-Encrypt(key_2, iv_2, plaintext)\n"
        "\n"
        "5. Send via WebSocket:\n"
        "   { content: ciphertext_for_recipient,   ephemeral_pub: ep1,  iv: iv1,\n"
        "     sender_copy: ciphertext_for_sender,  sender_ephemeral_pub: ep2,\n"
        "     sender_iv: iv2,  is_e2ee: true }"
    )

    pdf.h2("Server Storage (Zero Knowledge)")
    pdf.body(
        "The server stores ciphertext as-is and never sees plaintext for E2EE messages."
    )
    pdf.table(
        ["DB Column", "Contents"],
        [
            ["content",              "Recipient's ciphertext (base64)"],
            ["ephemeral_pub",        "Ephemeral public key for recipient key derivation"],
            ["iv",                   "AES-GCM nonce for recipient (base64)"],
            ["sender_copy",          "Sender's own ciphertext (base64)"],
            ["sender_ephemeral_pub", "Ephemeral public key for sender key derivation"],
            ["sender_iv",            "AES-GCM nonce for sender (base64)"],
            ["is_e2ee",              "Boolean flag  -  controls client decrypt path"],
        ],
        col_widths=[55, 115],
    )

    pdf.h2("Decryption Flow (Receiver's Browser)")
    pdf.code(
        "1. Receive new_message envelope via WebSocket\n"
        "2. Detect is_e2ee=true and message_type='direct'\n"
        "3. Select correct ciphertext pair:\n"
        "     Sender reads:    sender_copy + sender_ephemeral_pub + sender_iv\n"
        "     Recipient reads: content     + ephemeral_pub        + iv\n"
        "4. importKey(ephemeral_pub, SPKI) --> CryptoKey\n"
        "5. deriveKey(ECDH, ephemeral_pub, _privateKey) --> AES-256-GCM key\n"
        "6. AES-GCM decrypt(iv, ciphertext) --> plaintext\n"
        "7. Display in message bubble\n"
        "\n"
        "AES-GCM authentication: any tamper causes decrypt() to throw,\n"
        "producing 'Unable to decrypt message' in the UI."
    )

    pdf.h2("Historical Messages (Page Load)")
    pdf.body(
        "On dashboard load the server renders ciphertext into data-ct, data-ep, "
        "data-iv HTML attributes. After E2EE.init() resolves, decryptHistorical() "
        "walks every .e2ee-pending element and decrypts in-place."
    )

    pdf.h2("What Is NOT Encrypted")
    items = [
        "Broadcast messages  -  always plaintext (public by nature; per-recipient E2EE would require a ratchet protocol).",
        "File uploads  -  FileRecord.ephemeral_pub stores 'plain-text-prototype'; files are unencrypted on disk.",
        "Metadata  -  sender ID, receiver ID, timestamps, filenames always stored in plaintext.",
    ]
    for item in items:
        pdf.bullet(item)

    # -- Section 6: Message Flow -----------------------------------------------
    pdf.add_page()
    pdf.h1("6. Complete Message Flow")

    pdf.h2("Primary Path (WebSocket + E2EE)")
    pdf.code(
        "[User presses Enter]\n"
        "  |\n"
        "  |- receiverId == 'broadcast'?\n"
        "  |    \\- sendWs() --> plaintext over WebSocket\n"
        "  |\n"
        "  \\- DM?\n"
        "       |- pubkey in cache? YES --> _sendEncrypted()\n"
        "       \\- NO --> GET /api/users/<id>/pubkey --> cache --> _sendEncrypted()\n"
        "                          |\n"
        "                          v\n"
        "             E2EE.encryptFor(recipientPub) + E2EE.encryptFor(myPub)\n"
        "                          |\n"
        "                          v\n"
        "             socket.send('42[message, {type:send_message, payload:{...}}]')\n"
        "                          |\n"
        "                 [SERVER] handle_socket_message()\n"
        "                          |- rate limit check (30/min per user)\n"
        "                          |- build_message() -- validate receiver\n"
        "                          |- db.session.add(message) + commit\n"
        "                          \\- emit_saved_message()\n"
        "                                    |\n"
        "                                    |- emit --> room 'user_{sender_id}'\n"
        "                                    \\- emit --> room 'user_{receiver_id}'\n"
        "                                               |\n"
        "                                         dispatch() --> appendMessage()\n"
        "                                               |\n"
        "                                         E2EE.decrypt() --> display"
    )

    pdf.h2("HTTP Fallback Path")
    pdf.body(
        "If WebSocket is unavailable, the form submits as POST /messages. The server "
        "saves the message and redirects to the dashboard. This path always sends "
        "plaintext  -  no E2EE."
    )

    # -- Section 7: File Transfer ----------------------------------------------
    pdf.h1("7. File Transfer")

    pdf.h2("Standard Files (Images, Audio, Documents)")
    pdf.code(
        "POST /upload (multipart FormData)\n"
        "  |- extension whitelist check\n"
        "  |- size limit check (max 50 MB)\n"
        "  |- image/ --> Pillow: resize, strip EXIF, convert to WebP + thumbnail\n"
        "  |- audio/ --> FFmpeg: re-encode to Opus OGG\n"
        "  \\- other  --> save as-is\n"
        "  FileRecord + Message saved --> emit_saved_message() --> both parties notified"
    )

    pdf.h2("Video (Chunked Upload)")
    pdf.body(
        "Large videos are split into chunks (size determined by server-reported "
        "video_chunk_size based on connection tier) and sent sequentially to "
        "POST /upload/video/chunk. When all chunks arrive, a background thread:"
    )
    for step in [
        "Assembles chunks into a single raw file",
        "Extracts a poster frame with ffmpeg for the thumbnail",
        "Transcodes to H.264/AAC MP4 with ffmpeg",
        "Updates FileRecord.status from 'processing' to 'ready'",
        "Emits media_ready event to notify both parties instantly",
    ]:
        pdf.bullet(step)

    pdf.h2("Adaptive Quality (Connection Tiers)")
    pdf.body(
        "On every WebSocket connect the client measures RTT with GET /ping and "
        "reports a tier via the client_tier socket event."
    )
    pdf.table(
        ["Tier", "RTT", "Downlink", "Photo max", "Video CRF", "Scale"],
        [
            ["wired",      "< 5 ms",  "> 50 Mbps", "2560 px", "23", "1080p"],
            ["wifi_good",  "< 20 ms", "> 20 Mbps", "1920 px", "25", "720p"],
            ["wifi_weak",  "< 60 ms", "> 5 Mbps",  "1280 px", "28", "480p"],
            ["slow",       ">= 60 ms","<= 5 Mbps", "800 px",  "30", "360p"],
        ],
        col_widths=[28, 20, 28, 25, 25, 44],
    )
    pdf.body(
        "The server uses the worst tier across all active sessions of a user "
        "(multi-tab safe via client_tiers dict keyed by socket session ID)."
    )

    pdf.h2("File Access Control")
    pdf.table(
        ["Check", "Rule"],
        [
            ["Authentication",  "@login_required on all /uploads/* routes"],
            ["Ownership",       "uploader_id == current_user.id"],
            ["Direct share",    "receiver_id == current_user.id"],
            ["Broadcast files", "visibility == 'broadcast'"],
            ["Deleted files",   "404 returned regardless of ownership"],
            ["Processing",      "202 returned with retry_after:5 while transcoding"],
        ],
        col_widths=[45, 125],
    )

    # -- Section 8: Presence ---------------------------------------------------
    pdf.add_page()
    pdf.h1("8. Presence System")

    pdf.h2("Server-Side Data Structures")
    pdf.code(
        "_sid_to_uid: dict  # socket session ID --> user ID\n"
        "_uid_conns:  dict  # user ID --> active connection count (multi-tab safe)"
    )

    pdf.h2("Presence Events")
    pdf.table(
        ["Event", "Direction", "Trigger", "Payload"],
        [
            ["online_users", "Server -> connecting client",
             "On WebSocket connect", "{user_ids: [1, 3, 7]}  -  full snapshot"],
            ["user_online", "Server -> broadcast room",
             "First connection for a user", "{user_id: 5}"],
            ["user_offline", "Server -> broadcast room",
             "Last tab closed", "{user_id: 5}"],
            ["user_joined", "Server -> broadcast room",
             "New user registers", "{user_id, username, email, color_index, public_key}"],
        ],
        col_widths=[28, 38, 40, 64],
    )

    pdf.body(
        "Multi-tab safety: _uid_conns[uid] is a reference count. "
        "user_offline is only emitted when the count drops to zero (all tabs closed). "
        "user_online is only emitted when count rises from zero to one (first tab opened)."
    )

    # -- Section 9: Rate Limiting ----------------------------------------------
    pdf.h1("9. Rate Limiting")
    pdf.body(
        "Server-side only, stored in the _rate_limit in-memory dict. "
        "Limit: 30 messages per 60-second window per user. "
        "Exceeded requests receive a RATE_LIMITED error event over the socket. "
        "Stale past-minute windows are pruned on each check to prevent memory growth."
    )
    pdf.code(
        "_rate_limit: dict  # (user_id, minute_window) --> count\n"
        "\n"
        "window = int(time.time() // 60)  # current 1-minute bucket\n"
        "key = (user_id, window)\n"
        "if _rate_limit.get(key, 0) >= 30: reject with RATE_LIMITED"
    )

    # -- Section 10: Authorization ---------------------------------------------
    pdf.h1("10. Authorization Model")
    pdf.table(
        ["Action", "Requirement"],
        [
            ["View any page",          "@login_required  -  redirects to login if not authenticated"],
            ["Send a direct message",  "Authenticated + receiver must be active + not self"],
            ["Send broadcast",         "Authenticated  -  any active user"],
            ["Delete a message",       "Own messages only (msg.sender_id == current_user.id)"],
            ["Download a file",        "Uploader OR receiver OR broadcast visibility"],
            ["Admin dashboard",        "current_user.is_admin() (role == 'admin')"],
            ["Deactivate/activate user","Admin only  -  cannot deactivate own account"],
            ["Change user role",       "Admin only  -  cannot self-demote"],
        ],
        col_widths=[60, 110],
    )

    # -- Section 11: Database Schema -------------------------------------------
    pdf.add_page()
    pdf.h1("11. Database Schema")

    pdf.h2("users")
    pdf.table(
        ["Column", "Type", "Notes"],
        [
            ["id",            "INTEGER PK",     "Auto-increment"],
            ["username",      "VARCHAR(80)",    "Unique"],
            ["email",         "VARCHAR(120)",   "Unique, lowercase"],
            ["password_hash", "VARCHAR(256)",   "PBKDF2-SHA-256"],
            ["role",          "VARCHAR(20)",    "'admin' or 'user'"],
            ["is_active",     "BOOLEAN",        "Default True; admin-controlled"],
            ["public_key",    "TEXT",           "base64-SPKI ECDH P-256 public key"],
            ["created_at",    "DATETIME",       "UTC timestamp"],
        ],
        col_widths=[45, 35, 90],
    )

    pdf.h2("messages")
    pdf.table(
        ["Column", "Type", "Notes"],
        [
            ["id",                   "INTEGER PK",   ""],
            ["sender_id",            "INTEGER FK",   "-> users.id"],
            ["receiver_id",          "INTEGER FK",   "-> users.id; NULL for broadcast"],
            ["content",              "TEXT",         "Ciphertext (E2EE) or plaintext"],
            ["ephemeral_pub",        "TEXT",         "Recipient's ephemeral pub key (base64-SPKI)"],
            ["iv",                   "VARCHAR(64)",  "AES-GCM nonce for recipient"],
            ["is_e2ee",              "BOOLEAN",      "True if end-to-end encrypted"],
            ["sender_copy",          "TEXT",         "Sender's own ciphertext"],
            ["sender_ephemeral_pub", "TEXT",         "Sender's ephemeral pub key"],
            ["sender_iv",            "VARCHAR(64)",  "AES-GCM nonce for sender"],
            ["message_type",         "VARCHAR(20)",  "'direct' or 'broadcast'"],
            ["file_record_id",       "INTEGER FK",   "-> file_records.id; NULL if text-only"],
            ["is_deleted",           "BOOLEAN",      "Soft delete flag"],
            ["deleted_at",           "DATETIME",     "UTC timestamp of deletion"],
            ["timestamp",            "DATETIME",     "UTC timestamp of creation"],
        ],
        col_widths=[45, 30, 95],
    )

    pdf.h2("file_records")
    pdf.table(
        ["Column", "Type", "Notes"],
        [
            ["id",                "INTEGER PK",   ""],
            ["uploader_id",       "INTEGER FK",   "-> users.id"],
            ["receiver_id",       "INTEGER FK",   "-> users.id; NULL for broadcast"],
            ["original_filename", "VARCHAR(256)", "Sanitized via secure_filename()"],
            ["stored_filename",   "VARCHAR(256)", "UUID-based name on disk"],
            ["file_size",         "BIGINT",       "Original bytes"],
            ["mime_type",         "VARCHAR(128)", "Detected or Content-Type header"],
            ["ephemeral_pub",     "TEXT",         "'plain-text-prototype'  -  not yet encrypted"],
            ["iv",                "TEXT",         "'plain-text-prototype'  -  not yet encrypted"],
            ["visibility",        "VARCHAR(20)",  "'shared' (DM) or 'broadcast'"],
            ["status",            "VARCHAR(20)",  "'processing', 'ready', or 'failed'"],
            ["thumbnail_filename","VARCHAR(256)", "Thumb WebP/JPG on disk"],
            ["original_size",     "BIGINT",       "Pre-processing bytes"],
            ["processed_size",    "BIGINT",       "Post-processing bytes"],
            ["upload_tier",       "VARCHAR(20)",  "Connection tier at upload time"],
            ["media_width",       "INTEGER",      "Pixels (images)"],
            ["media_height",      "INTEGER",      "Pixels (images)"],
            ["media_duration",    "REAL",         "Seconds (audio/video)"],
            ["download_count",    "INTEGER",      "Unique-user download count"],
            ["uploaded_at",       "DATETIME",     "UTC timestamp"],
        ],
        col_widths=[45, 30, 95],
    )

    # -- Section 12: Gaps ------------------------------------------------------
    pdf.add_page()
    pdf.h1("12. Known Gaps / Not Yet Implemented")
    pdf.table(
        ["Feature", "Status"],
        [
            ["File encryption at rest",
             "FileRecord.ephemeral_pub stores 'plain-text-prototype'  -  files on disk are unencrypted."],
            ["Forward secrecy",
             "Not implemented. Private key compromise exposes all past messages for that key."],
            ["Key rotation",
             "No mechanism to rotate identity keys without clearing localStorage."],
            ["Broadcast E2EE",
             "Broadcast messages are always plaintext; ratchet protocol not implemented."],
            ["Server-side integrity",
             "Server stores ciphertext blindly  -  no HMAC over metadata."],
            ["Signal-style ratchet",
             "Each message uses fresh ECIES but there is no Double Ratchet for forward secrecy between messages."],
            ["Audit log",
             "No log of admin actions (deactivation, role changes)."],
        ],
        col_widths=[55, 115],
    )

    # -- Section 13: Security Summary ------------------------------------------
    pdf.h1("13. Security Properties Summary")
    pdf.table(
        ["Property", "Status", "Notes"],
        [
            ["DM text confidentiality", "YES",
             "AES-256-GCM; server stores only ciphertext"],
            ["DM text integrity",       "YES",
             "GCM auth tag  -  any tamper causes decrypt failure"],
            ["File confidentiality",    "NO",
             "Files stored unencrypted on disk"],
            ["Broadcast confidentiality","NO",
             "Always plaintext; visible to all LAN users"],
            ["Transport security",      "YES",
             "TLS (self-signed) on all HTTP and WebSocket traffic"],
            ["Password security",       "YES",
             "PBKDF2-SHA-256 via Werkzeug"],
            ["Resource authorization",  "YES",
             "Per-route and per-resource checks enforced server-side"],
            ["Key distribution trust",  "PARTIAL",
             "Server distributes public keys  -  a compromised server could MITM"],
            ["Perfect forward secrecy", "PARTIAL",
             "Ephemeral keys per message but no ratchet; private key compromise exposes history"],
            ["Replay protection",       "PARTIAL",
             "Unique IV per message; no explicit sequence numbers"],
        ],
        col_widths=[52, 18, 100],
    )

    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(
        0, 5,
        "YES = implemented and verified in the current codebase.  "
        "NO = not implemented.  "
        "PARTIAL = partially addressed; see notes.",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )

    return pdf


if __name__ == "__main__":
    pdf = build()
    out = "D:/IntraComms/IntraComms_Architecture.pdf"
    pdf.output(out)
    print(f"PDF written to: {out}")
