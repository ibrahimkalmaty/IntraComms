import base64
import json
import mimetypes
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path


import click
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, url_for

try:
    from PIL import Image, ImageOps
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    _APSCHEDULER_AVAILABLE = True
except ImportError:
    _APSCHEDULER_AVAILABLE = False
from flask_login import (  # type: ignore[import]
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_socketio import SocketIO, emit, join_room  # type: ignore[import]
from sqlalchemy import text as sa_text
from sqlalchemy.orm import joinedload

try:
    from .models import FileRecord, Message, User, db
except ImportError:
    from models import FileRecord, Message, User, db


BASE_DIR = Path(__file__).resolve().parent.parent
_TEMP_DIR = Path(tempfile.gettempdir())

login_manager = LoginManager()
login_manager.login_view = "login"
socketio = SocketIO()

_rate_limit: dict = {}          # (user_id, minute_window) → message count
_download_counted: set = set()  # (user_id, file_id) — one DB write per unique download
client_tiers: dict = {}         # sid → {tier, rtt, user_id}
_sid_to_uid: dict = {}          # sid → user_id  (for presence tracking)
_uid_conns: dict = {}           # user_id → connection count

# ── Adaptive media config keyed by connection tier ────────────────────────────
MEDIA_CONFIG: dict = {
    "wired": {
        "photo_max_dim": 2560, "photo_quality": 88,
        "photo_thumb_dim": 320, "photo_thumb_q": 75, "photo_compress": False,
        "video_chunk_size": 20 * 1024 * 1024, "video_crf": 23,
        "video_scale": "1080", "video_preset": "fast",
        "audio_bitrate": "64k",
        "max_age": 86400 * 7,
    },
    "wifi_good": {
        "photo_max_dim": 1920, "photo_quality": 85,
        "photo_thumb_dim": 240, "photo_thumb_q": 72, "photo_compress": True,
        "video_chunk_size": 5 * 1024 * 1024, "video_crf": 25,
        "video_scale": "720", "video_preset": "fast",
        "audio_bitrate": "48k",
        "max_age": 86400 * 3,
    },
    "wifi_weak": {
        "photo_max_dim": 1280, "photo_quality": 80,
        "photo_thumb_dim": 160, "photo_thumb_q": 65, "photo_compress": True,
        "video_chunk_size": 2 * 1024 * 1024, "video_crf": 28,
        "video_scale": "480", "video_preset": "veryfast",
        "audio_bitrate": "32k",
        "max_age": 86400 * 7,
    },
    "slow": {
        "photo_max_dim": 800, "photo_quality": 75,
        "photo_thumb_dim": 120, "photo_thumb_q": 60, "photo_compress": True,
        "video_chunk_size": 1 * 1024 * 1024, "video_crf": 30,
        "video_scale": "360", "video_preset": "ultrafast",
        "audio_bitrate": "24k",
        "max_age": 86400 * 14,
    },
}


def get_tier_for_user(user_id: int) -> str:
    """Return worst active tier for this user across all Socket.IO sessions."""
    tiers = [v["tier"] for v in client_tiers.values() if v.get("user_id") == user_id]
    order = ["slow", "wifi_weak", "wifi_good", "wired"]
    if not tiers:
        return "wifi_weak"
    return min(tiers, key=lambda t: order.index(t) if t in order else 0)


def cfg(user_id: int) -> dict:
    return MEDIA_CONFIG.get(get_tier_for_user(user_id), MEDIA_CONFIG["wifi_weak"])


def _ffmpeg_available() -> bool:
    return shutil.which("ffmpeg") is not None


# ── File encryption helpers ───────────────────────────────────────────────────

def _secure_delete(path: str) -> None:
    """Overwrite with zeros then delete. Best-effort on SSDs with wear leveling."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.write(b"\x00" * size)
        f.flush()
        os.fsync(f.fileno())
    os.remove(path)


def _seal_file_key(file_key_bytes: bytes, recipient_spki_b64: str) -> dict:
    """ECIES-seal a file key for one recipient using P-256 ECDH + AES-256-GCM."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH, SECP256R1, generate_private_key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    spki_bytes = base64.b64decode(recipient_spki_b64)
    recipient_pub = load_der_public_key(spki_bytes)

    ephemeral_priv = generate_private_key(SECP256R1())
    raw_shared = ephemeral_priv.exchange(ECDH(), recipient_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"intracomms-file-key-seal-v1",
    ).derive(raw_shared)

    iv = os.urandom(12)
    encrypted_key = AESGCM(aes_key).encrypt(iv, file_key_bytes, None)

    eph_pub_spki = ephemeral_priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "sealed":  base64.b64encode(encrypted_key).decode(),
        "eph_pub": base64.b64encode(eph_pub_spki).decode(),
        "iv":      base64.b64encode(iv).decode(),
    }


def encrypt_file_at_rest(
    file_path: str,
    recipient_pub_b64: str,
    sender_pub_b64: str | None = None,
) -> dict:
    """
    Encrypt a plaintext file in-place with a fresh AES-256-GCM key.
    The key is ECIES-sealed for the recipient (and optionally the sender).
    The plaintext file is securely deleted; ciphertext written to <path>.enc.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    file_key = os.urandom(32)
    file_iv  = os.urandom(12)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    ciphertext = AESGCM(file_key).encrypt(file_iv, plaintext, None)
    enc_path = file_path + ".enc"

    with open(enc_path, "wb") as f:
        f.write(ciphertext)

    _secure_delete(file_path)

    recipient_seal = _seal_file_key(file_key, recipient_pub_b64)
    result = {
        "stored_filename":   os.path.basename(enc_path),
        "file_iv":           base64.b64encode(file_iv).decode(),
        "sealed_key":        recipient_seal["sealed"],
        "key_ephemeral_pub": recipient_seal["eph_pub"],
        "key_iv":            recipient_seal["iv"],
        "encryption_type":   "server_at_rest",
    }

    if sender_pub_b64:
        sender_seal = _seal_file_key(file_key, sender_pub_b64)
        result.update({
            "sender_sealed_key":   sender_seal["sealed"],
            "sender_key_ephemeral": sender_seal["eph_pub"],
            "sender_key_iv":       sender_seal["iv"],
        })

    return result


def process_photo(raw_path: Path, base_name: str, upload_dir: Path, user_id: int) -> tuple:
    """Re-encode to WebP + generate square thumbnail. Returns (full_path, thumb_path, w, h)."""
    if not PILLOW_AVAILABLE:
        return raw_path, None, None, None

    c = cfg(user_id)
    with Image.open(raw_path) as img:
        img = ImageOps.exif_transpose(img)

        max_d = c["photo_max_dim"]
        img.thumbnail((max_d, max_d), Image.LANCZOS)

        if img.mode in ("RGBA", "P", "LA"):
            bg = Image.new("RGB", img.size, (255, 255, 255))
            mask = img.split()[-1] if "A" in img.mode else None
            bg.paste(img, mask=mask)
            img = bg
        elif img.mode != "RGB":
            img = img.convert("RGB")

        full_path = upload_dir / f"{base_name}.webp"
        thumb_path = upload_dir / f"{base_name}_thumb.webp"

        # exif=b"" strips all EXIF/metadata from the saved file
        img.save(str(full_path), "WEBP", quality=c["photo_quality"], method=6, exif=b"")

        td = c["photo_thumb_dim"]
        tw, th = img.size
        side = min(tw, th)
        thumb = img.crop(((tw - side) // 2, (th - side) // 2,
                          (tw - side) // 2 + side, (th - side) // 2 + side))
        thumb = thumb.resize((td, td), Image.LANCZOS)
        thumb.save(str(thumb_path), "WEBP", quality=c["photo_thumb_q"], method=4, exif=b"")

        w, h = img.size

    raw_path.unlink(missing_ok=True)
    return full_path, thumb_path, w, h


def process_audio(raw_path: Path, base_name: str, upload_dir: Path, user_id: int) -> tuple:
    """Re-encode audio to Opus OGG. Returns (out_path, duration, final_size)."""
    if not _ffmpeg_available():
        return raw_path, None, raw_path.stat().st_size

    c = cfg(user_id)
    out_path = upload_dir / f"{base_name}.ogg"
    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=nw=1:nk=1", str(raw_path)],
        capture_output=True, text=True,
    )
    duration = float(probe.stdout.strip() or 0)
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(raw_path),
         "-c:a", "libopus", "-b:a", c["audio_bitrate"],
         "-vbr", "on", "-application", "voip", str(out_path)],
        check=True, capture_output=True,
    )
    raw_path.unlink(missing_ok=True)
    return out_path, duration, out_path.stat().st_size


def _transcode_video(chunk_dir: Path, total_chunks: int, base_name: str,
                     upload_dir: Path, record_id: int, message_id: int,
                     sender_id: int, receiver_id, msg_type: str, tier: str) -> None:
    """Background thread: assemble chunks, transcode with FFmpeg, notify room."""
    c = MEDIA_CONFIG.get(tier, MEDIA_CONFIG["wifi_weak"])
    raw_path = chunk_dir / "assembled"
    out_path = upload_dir / f"{base_name}.mp4"
    thumb_path = upload_dir / f"{base_name}_thumb.jpg"

    try:
        with open(raw_path, "wb") as out_f:
            for i in range(total_chunks):
                chunk_file = chunk_dir / f"{i:05d}"
                with open(chunk_file, "rb") as cf:
                    shutil.copyfileobj(cf, out_f)

        if not thumb_path.exists() and _ffmpeg_available():
            subprocess.run(
                ["ffmpeg", "-y", "-i", str(raw_path),
                 "-ss", "00:00:01", "-vframes", "1",
                 "-vf", "scale=320:-2", str(thumb_path)],
                capture_output=True,
            )

        probe = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=nw=1:nk=1", str(raw_path)],
            capture_output=True, text=True,
        )
        duration = float(probe.stdout.strip() or 0)

        result = subprocess.run(
            ["ffmpeg", "-y", "-i", str(raw_path),
             "-c:v", "libx264", "-crf", str(c["video_crf"]),
             "-preset", c["video_preset"],
             "-c:a", "aac", "-b:a", "128k",
             "-vf", f"scale=-2:{c['video_scale']}",
             "-movflags", "+faststart",
             str(out_path)],
            capture_output=True,
        )
        shutil.rmtree(chunk_dir, ignore_errors=True)

        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode())

        final_size = out_path.stat().st_size

        with app.app_context():
            rec = db.session.get(FileRecord, record_id)
            if rec:
                # Encrypt at rest for direct messages when both parties have pubkeys
                if receiver_id is not None:
                    recipient = db.session.get(User, receiver_id)
                    sender    = db.session.get(User, sender_id)
                    if recipient and recipient.public_key:
                        try:
                            enc = encrypt_file_at_rest(
                                str(out_path),
                                recipient.public_key,
                                sender.public_key if sender and sender.public_key else None,
                            )
                            rec.stored_filename    = enc["stored_filename"]
                            rec.is_e2ee            = True
                            rec.encryption_type    = "server_at_rest"
                            rec.file_iv            = enc["file_iv"]
                            rec.sealed_key         = enc["sealed_key"]
                            rec.key_ephemeral_pub  = enc["key_ephemeral_pub"]
                            rec.key_iv             = enc["key_iv"]
                            rec.sender_sealed_key  = enc.get("sender_sealed_key")
                            rec.sender_key_ephemeral = enc.get("sender_key_ephemeral")
                            rec.sender_key_iv      = enc.get("sender_key_iv")
                            final_size = Path(app.config["UPLOAD_FOLDER"], enc["stored_filename"]).stat().st_size
                        except Exception as enc_err:
                            app.logger.error("Video at-rest encryption failed: %s", enc_err)

                rec.status = "ready"
                rec.processed_size = final_size
                rec.media_duration = duration
                if thumb_path.exists():
                    rec.thumbnail_filename = thumb_path.name
                db.session.commit()

        payload = {
            "media_id": record_id,
            "url": f"/uploads/{record_id}",
            "thumb_url": f"/uploads/{record_id}/thumb" if thumb_path.exists() else None,
            "duration": duration,
            "mime_type": "video/mp4",
        }
        envelope = {"type": "media_ready", "payload": payload}
        if msg_type == "broadcast":
            socketio.emit("message", envelope, room="broadcast")
        else:
            socketio.emit("message", envelope, room=f"user_{sender_id}")
            if receiver_id and receiver_id != sender_id:
                socketio.emit("message", envelope, room=f"user_{receiver_id}")

    except Exception as e:
        shutil.rmtree(chunk_dir, ignore_errors=True)
        with app.app_context():
            rec = db.session.get(FileRecord, record_id)
            if rec:
                rec.status = "failed"
                db.session.commit()
        err_env = {"type": "media_failed", "payload": {"media_id": record_id, "error": str(e)}}
        if msg_type == "broadcast":
            socketio.emit("message", err_env, room="broadcast")
        else:
            socketio.emit("message", err_env, room=f"user_{sender_id}")
            if receiver_id and receiver_id != sender_id:
                socketio.emit("message", err_env, room=f"user_{receiver_id}")


def is_rate_limited(user_id: int, limit: int = 30) -> bool:
    window = int(time.time() // 60)
    key = (user_id, window)
    for k in [k for k in list(_rate_limit) if k[1] < window]:
        del _rate_limit[k]
    count = _rate_limit.get(key, 0)
    if count >= limit:
        return True
    _rate_limit[key] = count + 1
    return False


def serialize_message(message: Message) -> dict:
    receiver_name = message.receiver.username if message.receiver else None
    fr = message.file_record
    file_data = None
    if fr:
        file_data = {
            "id": fr.id,
            "uploader_id": fr.uploader_id,
            "original_filename": fr.original_filename,
            "mime_type": fr.mime_type,
            "status": fr.status,
            "url": f"/uploads/{fr.id}",
            "thumb_url": f"/uploads/{fr.id}/thumb" if fr.thumbnail_filename else None,
            "media_category": fr.media_category(),
            "media_width": fr.media_width,
            "media_height": fr.media_height,
            "media_duration": fr.media_duration,
            "file_size": fr.file_size,
            "file_size_human": fr.file_size_human(),
            "original_size": fr.original_size,
            "processed_size": fr.processed_size,
            "upload_tier": fr.upload_tier,
            "is_e2ee": fr.is_e2ee,
            "encryption_type": fr.encryption_type,
            "hint_category": fr.hint_category,
        }
    return {
        "id": message.id,
        "sender_id": message.sender_id,
        "sender_username": message.sender.username if message.sender else "Unknown",
        "receiver_id": message.receiver_id,
        "receiver_username": receiver_name,
        "content": message.content,
        "ephemeral_pub": message.ephemeral_pub,
        "iv": message.iv,
        "sender_copy":          message.sender_copy,
        "sender_ephemeral_pub": message.sender_ephemeral_pub,
        "sender_iv":            message.sender_iv,
        "is_e2ee": message.is_e2ee,
        "message_type": message.message_type,
        "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M"),
        "file_record": file_data,
        "is_deleted": message.is_deleted,
    }


def build_message(
    sender: User,
    receiver_id: str,
    content: str,
    ephemeral_pub: str = "plain-text-prototype",
    msg_iv: str = "plain-text-prototype",
    is_e2ee: bool = False,
    sender_copy: str | None = None,
    sender_ephemeral_pub: str | None = None,
    sender_iv: str | None = None,
) -> tuple[Message | None, str | None]:
    content = content.strip()
    receiver_id = receiver_id.strip()

    if not content:
        return None, "Message cannot be empty."

    if receiver_id == "broadcast":
        return (
            Message(
                sender_id=sender.id,
                receiver_id=None,
                content=content,
                ephemeral_pub="plain-text-prototype",
                iv="plain-text-prototype",
                is_e2ee=False,   # broadcast messages are never E2EE
                message_type="broadcast",
            ),
            None,
        )

    try:
        receiver_id_int = int(receiver_id)
    except ValueError:
        return None, "Choose a valid recipient."

    receiver = db.session.get(User, receiver_id_int)
    if not receiver or not receiver.is_active or receiver.id == sender.id:
        return None, "Choose a valid recipient."

    return (
        Message(
            sender_id=sender.id,
            receiver_id=receiver.id,
            content=content,
            ephemeral_pub=ephemeral_pub,
            iv=msg_iv,
            is_e2ee=is_e2ee,
            sender_copy=sender_copy,
            sender_ephemeral_pub=sender_ephemeral_pub,
            sender_iv=sender_iv,
            message_type="direct",
        ),
        None,
    )


def emit_saved_message(message: Message, request_id: str = "") -> None:
    envelope = {
        "type": "new_message",
        "payload": serialize_message(message),
        "requestId": request_id,
        "status": "ok",
    }
    if message.is_broadcast():
        socketio.emit("message", envelope, room="broadcast")
        return

    socketio.emit("message", envelope, room=f"user_{message.sender_id}")
    if message.receiver_id != message.sender_id:
        socketio.emit("message", envelope, room=f"user_{message.receiver_id}")


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-me"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", f"sqlite:///{BASE_DIR / 'intracomms.db'}"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=50 * 1024 * 1024,
        UPLOAD_FOLDER=str(BASE_DIR / "uploads"),
    )

    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    register_routes(app)
    register_cli(app)

    # Idempotent schema migrations — each silently no-ops if column already exists
    _migrations = [
        "ALTER TABLE messages ADD COLUMN file_record_id INTEGER REFERENCES file_records(id)",
        "ALTER TABLE messages ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0",
        "ALTER TABLE messages ADD COLUMN deleted_at DATETIME",
        "ALTER TABLE file_records ADD COLUMN status VARCHAR(20) DEFAULT 'ready'",
        "ALTER TABLE file_records ADD COLUMN thumbnail_filename VARCHAR(256)",
        "ALTER TABLE file_records ADD COLUMN original_size BIGINT",
        "ALTER TABLE file_records ADD COLUMN processed_size BIGINT",
        "ALTER TABLE file_records ADD COLUMN upload_tier VARCHAR(20)",
        "ALTER TABLE file_records ADD COLUMN media_width INTEGER",
        "ALTER TABLE file_records ADD COLUMN media_height INTEGER",
        "ALTER TABLE file_records ADD COLUMN media_duration REAL",
        "ALTER TABLE messages ADD COLUMN is_e2ee BOOLEAN NOT NULL DEFAULT 0",
        "ALTER TABLE messages RENAME COLUMN aes_key_encrypted TO ephemeral_pub",
        "ALTER TABLE messages ADD COLUMN sender_copy TEXT",
        "ALTER TABLE messages ADD COLUMN sender_ephemeral_pub TEXT",
        "ALTER TABLE messages ADD COLUMN sender_iv VARCHAR(64)",
        "ALTER TABLE file_records RENAME COLUMN aes_key_encrypted TO ephemeral_pub",
        "ALTER TABLE file_records ADD COLUMN is_e2ee BOOLEAN NOT NULL DEFAULT 0",
        "ALTER TABLE file_records ADD COLUMN encryption_type VARCHAR(32)",
        "ALTER TABLE file_records ADD COLUMN file_iv VARCHAR(64)",
        "ALTER TABLE file_records ADD COLUMN sealed_key TEXT",
        "ALTER TABLE file_records ADD COLUMN key_ephemeral_pub TEXT",
        "ALTER TABLE file_records ADD COLUMN key_iv VARCHAR(64)",
        "ALTER TABLE file_records ADD COLUMN sender_sealed_key TEXT",
        "ALTER TABLE file_records ADD COLUMN sender_key_ephemeral TEXT",
        "ALTER TABLE file_records ADD COLUMN sender_key_iv VARCHAR(64)",
        "ALTER TABLE file_records ADD COLUMN encrypted_meta TEXT",
        "ALTER TABLE file_records ADD COLUMN hint_category VARCHAR(16)",
        "ALTER TABLE users ADD COLUMN encrypted_priv_key TEXT",
        "ALTER TABLE users ADD COLUMN key_salt VARCHAR(32)",
    ]
    with app.app_context():
        for sql in _migrations:
            try:
                with db.engine.connect() as conn:
                    conn.execute(sa_text(sql))
                    conn.commit()
            except Exception:
                pass

    return app


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return db.session.get(User, int(user_id))


def register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create database tables for the current models."""
        with app.app_context():
            db.create_all()
        print("Database initialized.")

    @app.cli.command("clear-db")
    def clear_db_command() -> None:
        """Drop all tables and recreate them (wipes all data)."""
        with app.app_context():
            db.drop_all()
            db.create_all()
        print("Database cleared and re-initialized.")

    @app.cli.command("promote-admin")
    @click.argument("username")
    def promote_admin_command(username: str) -> None:
        """Promote a user to admin by username."""
        username = username.strip()
        if not username:
            print("Username is required.")
            return

        with app.app_context():
            user = User.query.filter_by(username=username).first()
            if not user:
                print(f"User {username!r} was not found.")
                return

            user.role = "admin"
            user.is_active = True
            db.session.commit()
            print(f"User {username!r} is now an admin.")


def register_routes(app: Flask) -> None:
    def require_admin() -> None:
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)

    @app.route("/ping")
    def ping():
        return "", 204

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            public_key = request.form.get("public_key", "").strip() or None

            if not username or not email or not password:
                flash("Username, email, and password are required.", "error")
                return render_template("register.html")

            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
            if existing_user:
                flash("A user with that username or email already exists.", "error")
                return render_template("register.html")

            role = "admin" if User.query.count() == 0 else "user"
            user = User(username=username, email=email, public_key=public_key, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            login_user(user)
            flash("Account created.", "success")
            socketio.emit("message", {
                "type": "user_joined",
                "payload": {
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "color_index": user.id % 8,
                    "public_key": user.public_key,
                },
            }, room="broadcast")
            return redirect(url_for("dashboard"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = User.query.filter_by(username=username).first()

            if not user or not user.check_password(password):
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            if not user.is_active:
                flash("This account is inactive.", "error")
                return render_template("login.html")

            login_user(user)
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        users = User.query.filter(User.id != current_user.id, User.is_active.is_(True)).all()
        messages = list(
            Message.query.options(joinedload(Message.file_record))
            .filter(
                (Message.receiver_id == current_user.id)
                | (Message.sender_id == current_user.id)
                | (Message.message_type == "broadcast")
            )
            .order_by(Message.timestamp.desc())
            .limit(200)
            .all()
        )
        messages.reverse()

        # Build recent conversations — latest message per chat, sorted newest first
        broadcast_last = None
        dm_latest: dict = {}
        for msg in messages:
            if msg.message_type == "broadcast":
                broadcast_last = msg
            else:
                partner_id = msg.receiver_id if msg.sender_id == current_user.id else msg.sender_id
                partner = msg.receiver if msg.sender_id == current_user.id else msg.sender
                if partner:
                    dm_latest[partner_id] = {
                        "key": str(partner_id),
                        "name": partner.username,
                        "kind": "direct",
                        "color_index": partner_id % 8,
                        "last_content": msg.content,
                        "last_time": msg.timestamp,
                        "sender_is_me": msg.sender_id == current_user.id,
                    }

        dm_list = sorted(dm_latest.values(), key=lambda x: x["last_time"], reverse=True)
        recent_convos = [{
            "key": "broadcast",
            "name": "Everyone",
            "kind": "broadcast",
            "color_index": None,
            "last_content": broadcast_last.content if broadcast_last else "",
            "last_time": broadcast_last.timestamp if broadcast_last else None,
            "sender_is_me": (broadcast_last.sender_id == current_user.id) if broadcast_last else False,
        }] + dm_list

        user_pubkeys = {str(u.id): u.public_key for u in users if u.public_key}
        return render_template(
            "dashboard.html",
            users=users,
            messages=messages,
            recent_convos=recent_convos,
            user_pubkeys=user_pubkeys,
        )

    @app.route("/messages/<int:msg_id>/delete", methods=["POST"])
    @login_required
    def delete_message(msg_id: int):
        msg = db.session.get(Message, msg_id)
        if not msg or msg.sender_id != current_user.id:
            return jsonify({"error": "Not found or not authorized."}), 403
        if msg.is_deleted:
            return jsonify({"status": "ok"})

        msg.soft_delete()
        if msg.file_record and not msg.file_record.is_deleted:
            msg.file_record.soft_delete()
        db.session.commit()

        deletion_envelope = {
            "type": "message_deleted",
            "payload": {"message_id": msg.id},
        }
        if msg.is_broadcast():
            socketio.emit("message", deletion_envelope, room="broadcast")
        else:
            socketio.emit("message", deletion_envelope, room=f"user_{msg.sender_id}")
            if msg.receiver_id and msg.receiver_id != msg.sender_id:
                socketio.emit("message", deletion_envelope, room=f"user_{msg.receiver_id}")

        return jsonify({"status": "ok"})

    @app.route("/upload", methods=["POST"])
    @login_required
    def upload_file():
        if is_rate_limited(current_user.id):
            return jsonify({"error": "Too many requests."}), 429

        file = request.files.get("file")
        if not file or not file.filename:
            return jsonify({"error": "No file provided."}), 400

        from werkzeug.utils import secure_filename
        original_name = secure_filename(file.filename)
        if not original_name:
            return jsonify({"error": "Invalid filename."}), 400

        ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
        if not FileRecord.is_allowed_extension(original_name):
            return jsonify({"error": f"File type .{ext} is not allowed."}), 415

        file.seek(0, 2)
        orig_size = file.tell()
        file.seek(0)
        if not FileRecord.is_within_size_limit(orig_size):
            return jsonify({"error": "File too large (max 50 MB)."}), 413

        receiver_id_str = request.form.get("receiver_id", "broadcast").strip()
        if receiver_id_str == "broadcast":
            receiver_id = None
            msg_type = "broadcast"
            visibility = "broadcast"
        else:
            try:
                receiver_id_int = int(receiver_id_str)
            except ValueError:
                return jsonify({"error": "Invalid recipient."}), 400
            recipient = db.session.get(User, receiver_id_int)
            if not recipient or not recipient.is_active or recipient.id == current_user.id:
                return jsonify({"error": "Invalid recipient."}), 400
            receiver_id = recipient.id
            msg_type = "direct"
            visibility = "shared"

        tier = get_tier_for_user(current_user.id)
        upload_dir = Path(app.config["UPLOAD_FOLDER"])
        upload_dir.mkdir(parents=True, exist_ok=True)
        base_name = uuid.uuid4().hex

        mime_type = (
            file.content_type
            or mimetypes.guess_type(original_name)[0]
            or "application/octet-stream"
        )

        # Save raw file first
        raw_ext = ext if ext else "bin"
        raw_path = upload_dir / f"{base_name}_raw.{raw_ext}"
        file.save(str(raw_path))

        stored_name = f"{base_name}.{raw_ext}"
        thumbnail_filename = None
        media_width = media_height = media_duration = None
        processed_size = orig_size

        # ── Photo pipeline ────────────────────────────────────────────────────
        if mime_type.startswith("image/") and PILLOW_AVAILABLE:
            try:
                full_path, thumb_path, w, h = process_photo(
                    raw_path, base_name, upload_dir, current_user.id
                )
                stored_name = f"{base_name}.webp"
                mime_type = "image/webp"
                processed_size = full_path.stat().st_size
                media_width, media_height = w, h
                if thumb_path and thumb_path.exists():
                    thumbnail_filename = thumb_path.name
            except Exception:
                # Pillow failed; fall back to raw file
                raw_path.rename(upload_dir / stored_name)

        # ── Audio pipeline ────────────────────────────────────────────────────
        elif mime_type.startswith("audio/") and _ffmpeg_available():
            try:
                out_path, duration, final_size = process_audio(
                    raw_path, base_name, upload_dir, current_user.id
                )
                stored_name = f"{base_name}.ogg"
                mime_type = "audio/ogg"
                processed_size = final_size
                media_duration = duration
            except Exception:
                raw_path.rename(upload_dir / stored_name)
        else:
            raw_path.rename(upload_dir / stored_name)

        record = FileRecord(
            uploader_id=current_user.id,
            receiver_id=receiver_id,
            original_filename=original_name,
            stored_filename=stored_name,
            file_size=orig_size,
            mime_type=mime_type,
            ephemeral_pub="plain-text-prototype",
            iv="plain-text-prototype",
            visibility=visibility,
            status="ready",
            thumbnail_filename=thumbnail_filename,
            original_size=orig_size,
            processed_size=processed_size,
            upload_tier=tier,
            media_width=media_width,
            media_height=media_height,
            media_duration=media_duration,
        )
        db.session.add(record)
        db.session.flush()

        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            content=original_name,
            ephemeral_pub="plain-text-prototype",
            iv="plain-text-prototype",
            message_type=msg_type,
            file_record_id=record.id,
        )
        db.session.add(message)
        db.session.commit()
        emit_saved_message(message)
        return jsonify({"status": "ok", "message_id": message.id})

    @app.route("/upload/video/chunk", methods=["POST"])
    @login_required
    def upload_video_chunk():
        if is_rate_limited(current_user.id):
            return jsonify({"error": "Too many requests."}), 429

        media_id   = request.form.get("media_id", "").strip()
        chunk_idx  = request.form.get("chunk_index", "0")
        total      = request.form.get("total_chunks", "1")
        chunk_file = request.files.get("chunk")
        filename   = request.form.get("filename", "video.mp4")
        receiver_id_str = request.form.get("receiver_id", "broadcast").strip()
        poster_b64 = request.form.get("poster_b64", "")

        if not media_id or not chunk_file:
            return jsonify({"error": "Missing media_id or chunk."}), 400

        try:
            chunk_idx = int(chunk_idx)
            total = int(total)
        except ValueError:
            return jsonify({"error": "Invalid chunk parameters."}), 400

        chunk_dir = _TEMP_DIR / f"vid_{media_id}"
        chunk_dir.mkdir(parents=True, exist_ok=True)
        chunk_file.save(str(chunk_dir / f"{chunk_idx:05d}"))

        received = len(list(chunk_dir.glob("[0-9]*")))
        if received < total:
            return jsonify({"status": "chunk_saved", "received": received})

        # All chunks received — determine routing
        if receiver_id_str == "broadcast":
            receiver_id = None
            msg_type = "broadcast"
            visibility = "broadcast"
        else:
            try:
                rid = int(receiver_id_str)
            except ValueError:
                return jsonify({"error": "Invalid recipient."}), 400
            recipient = db.session.get(User, rid)
            if not recipient or not recipient.is_active or recipient.id == current_user.id:
                return jsonify({"error": "Invalid recipient."}), 400
            receiver_id = recipient.id
            msg_type = "direct"
            visibility = "shared"

        tier = get_tier_for_user(current_user.id)
        upload_dir = Path(app.config["UPLOAD_FOLDER"])
        upload_dir.mkdir(parents=True, exist_ok=True)

        # Save poster thumbnail if provided by client
        thumb_filename = None
        if poster_b64:
            try:
                import base64
                raw_b64 = poster_b64.split(",")[1] if "," in poster_b64 else poster_b64
                thumb_path = upload_dir / f"{media_id}_thumb.jpg"
                thumb_path.write_bytes(base64.b64decode(raw_b64))
                thumb_filename = thumb_path.name
            except Exception:
                pass

        from werkzeug.utils import secure_filename
        original_name = secure_filename(filename) or "video.mp4"

        record = FileRecord(
            uploader_id=current_user.id,
            receiver_id=receiver_id,
            original_filename=original_name,
            stored_filename=f"{media_id}.mp4",
            file_size=0,
            mime_type="video/mp4",
            ephemeral_pub="plain-text-prototype",
            iv="plain-text-prototype",
            visibility=visibility,
            status="processing",
            thumbnail_filename=thumb_filename,
            upload_tier=tier,
        )
        db.session.add(record)
        db.session.flush()

        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            content=original_name,
            ephemeral_pub="plain-text-prototype",
            iv="plain-text-prototype",
            message_type=msg_type,
            file_record_id=record.id,
        )
        db.session.add(message)
        db.session.commit()
        emit_saved_message(message)

        # Kick off background transcode
        t = threading.Thread(
            target=_transcode_video,
            args=(chunk_dir, total, media_id, upload_dir,
                  record.id, message.id,
                  current_user.id, receiver_id, msg_type, tier),
            daemon=True,
        )
        t.start()

        return jsonify({"status": "assembling", "message_id": message.id})

    def _user_can_access(record: FileRecord) -> bool:
        return (
            record.uploader_id == current_user.id
            or record.receiver_id == current_user.id
            or record.visibility == "broadcast"
        )

    # ── E2EE upload ──────────────────────────────────────────────────────────

    @app.route("/upload/e2ee", methods=["POST"])
    @login_required
    def upload_e2ee_file():
        """Receive a client-side encrypted file. Server stores opaque blob + key material only."""
        if is_rate_limited(current_user.id):
            return jsonify({"error": "Too many requests."}), 429

        receiver_id_str   = request.form.get("receiver_id", "").strip()
        file_iv           = request.form.get("file_iv", "").strip()
        sealed_key        = request.form.get("sealed_key", "").strip()
        key_ephemeral_pub = request.form.get("key_ephemeral_pub", "").strip()
        key_iv            = request.form.get("key_iv", "").strip()
        sender_sealed_key = request.form.get("sender_sealed_key", "").strip() or None
        sender_key_eph    = request.form.get("sender_key_ephemeral", "").strip() or None
        sender_key_iv     = request.form.get("sender_key_iv", "").strip() or None
        encrypted_meta    = request.form.get("encrypted_meta", "").strip() or None
        hint_category     = request.form.get("hint_category", "file").strip()
        if hint_category not in ("image", "video", "audio", "file"):
            hint_category = "file"
        encrypted_file    = request.files.get("file")

        if not all([receiver_id_str, file_iv, sealed_key, key_ephemeral_pub, key_iv, encrypted_file]):
            return jsonify({"error": "missing required fields"}), 400

        if receiver_id_str == "broadcast":
            return jsonify({"error": "E2EE uploads require a direct recipient"}), 400

        try:
            receiver_id = int(receiver_id_str)
        except ValueError:
            return jsonify({"error": "invalid receiver_id"}), 400

        receiver = db.session.get(User, receiver_id)
        if not receiver or not receiver.is_active or receiver.id == current_user.id:
            return jsonify({"error": "invalid receiver"}), 404

        stored_name = secrets.token_hex(32) + ".enc"
        dest_path = Path(app.config["UPLOAD_FOLDER"]) / stored_name
        encrypted_file.save(str(dest_path))

        raw_name = request.form.get("original_filename", "").strip()
        safe_name = raw_name[:256] if raw_name else "[encrypted]"

        record = FileRecord(
            uploader_id       = current_user.id,
            receiver_id       = receiver_id,
            original_filename = safe_name,
            stored_filename   = stored_name,
            file_size         = dest_path.stat().st_size,
            mime_type         = "application/octet-stream",
            ephemeral_pub     = "e2ee",
            iv                = "e2ee",
            visibility        = "shared",
            status            = "ready",
            is_e2ee           = True,
            encryption_type   = "client_e2ee",
            file_iv           = file_iv,
            sealed_key        = sealed_key,
            key_ephemeral_pub = key_ephemeral_pub,
            key_iv            = key_iv,
            sender_sealed_key = sender_sealed_key,
            sender_key_ephemeral = sender_key_eph,
            sender_key_iv     = sender_key_iv,
            encrypted_meta    = encrypted_meta,
            hint_category     = hint_category,
        )
        db.session.add(record)
        db.session.flush()

        message = Message(
            sender_id    = current_user.id,
            receiver_id  = receiver_id,
            content      = "",
            ephemeral_pub = "e2ee",
            iv            = "e2ee",
            is_e2ee      = True,
            message_type = "direct",
            file_record_id = record.id,
        )
        db.session.add(message)
        db.session.commit()
        emit_saved_message(message)

        return jsonify({"status": "stored", "file_record_id": record.id, "message_id": message.id})

    @app.route("/uploads/<int:file_id>/meta")
    @login_required
    def get_file_meta(file_id: int):
        """Return key material for an E2EE file. Server returns the correct sealed copy."""
        record = db.session.get(FileRecord, file_id)
        if not record or record.is_deleted:
            abort(404)
        if not _user_can_access(record):
            abort(403)
        if not record.is_e2ee:
            return jsonify({"error": "not an E2EE file"}), 400

        is_sender = (record.uploader_id == current_user.id)

        return jsonify({
            "file_id":           record.id,
            "encryption_type":   record.encryption_type,
            "file_iv":           record.file_iv,
            "sealed_key":        record.sender_sealed_key if is_sender else record.sealed_key,
            "key_ephemeral_pub": record.sender_key_ephemeral if is_sender else record.key_ephemeral_pub,
            "key_iv":            record.sender_key_iv if is_sender else record.key_iv,
            "encrypted_meta":    json.loads(record.encrypted_meta) if record.encrypted_meta else None,
        })

    @app.route("/uploads/<int:file_id>/blob")
    @login_required
    def get_file_blob(file_id: int):
        """Serve the raw encrypted blob for client-side decryption."""
        record = db.session.get(FileRecord, file_id)
        if not record or record.is_deleted:
            abort(404)
        if not _user_can_access(record):
            abort(403)
        if not record.is_e2ee:
            abort(400)
        if record.status == "processing":
            return jsonify({"status": "processing", "retry_after": 5}), 202

        file_path = Path(app.config["UPLOAD_FOLDER"]) / record.stored_filename
        if not file_path.exists():
            abort(404)

        count_key = (current_user.id, file_id)
        if count_key not in _download_counted:
            record.increment_download()
            db.session.commit()
            _download_counted.add(count_key)

        response = send_file(str(file_path), mimetype="application/octet-stream")
        response.headers["Cache-Control"] = "private, no-store"
        return response

    # ── Plain file serving ────────────────────────────────────────────────────

    @app.route("/uploads/<int:file_id>")
    @login_required
    def serve_file(file_id: int):
        record = db.session.get(FileRecord, file_id)
        if not record or record.is_deleted:
            abort(404)
        if not _user_can_access(record):
            abort(403)

        # E2EE files must be fetched via /blob + /meta
        if record.is_e2ee:
            return jsonify({"error": "use /uploads/<id>/blob and /uploads/<id>/meta"}), 403

        # Block access while still transcoding
        if record.status == "processing":
            return jsonify({"status": "processing", "retry_after": 5}), 202
        if record.status == "failed":
            abort(410)

        file_path = Path(app.config["UPLOAD_FOLDER"]) / record.stored_filename
        if not file_path.exists():
            abort(404)

        count_key = (current_user.id, file_id)
        if count_key not in _download_counted:
            record.increment_download()
            db.session.commit()
            _download_counted.add(count_key)

        tier = get_tier_for_user(current_user.id)
        max_age = MEDIA_CONFIG.get(tier, MEDIA_CONFIG["wifi_weak"])["max_age"]

        is_media = record.media_category() in ("image", "video", "audio")
        response = send_file(
            str(file_path),
            mimetype=record.mime_type or "application/octet-stream",
            as_attachment=not is_media,
            download_name=record.original_filename,
            conditional=True,
        )
        response.headers["Cache-Control"] = f"private, max-age={max_age}"
        return response

    @app.route("/uploads/<int:file_id>/thumb")
    @login_required
    def serve_thumbnail(file_id: int):
        record = db.session.get(FileRecord, file_id)
        if not record or record.is_deleted:
            abort(404)
        if not _user_can_access(record):
            abort(403)
        if not record.thumbnail_filename:
            abort(404)

        thumb_path = Path(app.config["UPLOAD_FOLDER"]) / record.thumbnail_filename
        if not thumb_path.exists():
            abort(404)

        mime = "image/webp" if record.thumbnail_filename.endswith(".webp") else "image/jpeg"
        response = send_file(str(thumb_path), mimetype=mime, conditional=True)
        response.headers["Cache-Control"] = "private, max-age=604800"
        return response

    @app.route("/admin")
    @login_required
    def admin_dashboard():
        require_admin()
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("admin_dashboard.html", users=users)

    @app.route("/admin/users/<int:user_id>/deactivate", methods=["POST"])
    @login_required
    def admin_deactivate_user(user_id: int):
        require_admin()
        user = db.session.get(User, user_id) or abort(404)

        if user.id == current_user.id:
            flash("You cannot deactivate your own admin account.", "error")
            return redirect(url_for("admin_dashboard"))

        user.is_active = False
        db.session.commit()
        flash(f"{user.username} has been deactivated.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.route("/admin/users/<int:user_id>/activate", methods=["POST"])
    @login_required
    def admin_activate_user(user_id: int):
        require_admin()
        user = db.session.get(User, user_id) or abort(404)
        user.is_active = True
        db.session.commit()
        flash(f"{user.username} has been activated.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.route("/admin/users/<int:user_id>/role", methods=["POST"])
    @login_required
    def admin_update_role(user_id: int):
        require_admin()
        user = db.session.get(User, user_id) or abort(404)
        role = request.form.get("role", "user")

        if role not in {"admin", "user"}:
            abort(400)

        if user.id == current_user.id and role != "admin":
            flash("You cannot remove admin access from your own account.", "error")
            return redirect(url_for("admin_dashboard"))

        user.role = role
        db.session.commit()
        flash(f"{user.username} is now {role}.", "success")
        return redirect(url_for("admin_dashboard"))

    # ── E2EE key management ────────────────────────────────────────────────────

    @app.route("/api/me/pubkey", methods=["POST"])
    @login_required
    def update_my_pubkey():
        """Client POSTs its freshly generated X25519 public key (base64-SPKI)."""
        data = request.get_json(silent=True) or {}
        pk = str(data.get("public_key", "")).strip()
        if not pk:
            return jsonify({"error": "public_key required"}), 400
        if len(pk) > 4096:
            return jsonify({"error": "public_key too long"}), 400
        current_user.public_key = pk
        db.session.commit()
        return jsonify({"status": "ok"})

    @app.route("/api/me/fingerprint")
    @login_required
    def get_my_fingerprint():
        """Return own public key so the client can compute and display its own fingerprint."""
        return jsonify({"public_key": current_user.public_key})

    @app.route("/api/me/key-backup", methods=["GET"])
    @login_required
    def get_key_backup():
        if not current_user.encrypted_priv_key:
            return jsonify({"available": False})
        return jsonify({
            "available": True,
            "encrypted": current_user.encrypted_priv_key,
            "salt": current_user.key_salt,
        })

    @app.route("/api/me/key-backup", methods=["POST"])
    @login_required
    def store_key_backup():
        data = request.get_json(silent=True) or {}
        enc  = (data.get("encrypted") or "").strip()
        salt = (data.get("salt") or "").strip()
        if not enc or not salt:
            return jsonify({"error": "Missing fields"}), 400
        current_user.encrypted_priv_key = enc
        current_user.key_salt = salt
        db.session.commit()
        return jsonify({"status": "ok"})

    @app.route("/api/users/<int:user_id>/pubkey")
    @login_required
    def get_user_pubkey(user_id: int):
        """Return a user's public key so the sender can encrypt for them."""
        user = db.session.get(User, user_id)
        if not user or not user.is_active:
            return jsonify({"error": "not found"}), 404
        return jsonify({"public_key": user.public_key})


@socketio.on("p2p_offer")
def handle_p2p_offer(data):
    """Relay P2P file-transfer offer to recipient; inject server-verified sender identity."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    data["sender_id"]   = current_user.id
    data["sender_name"] = current_user.username
    emit("message", {"type": "p2p_offer", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("p2p_answer")
def handle_p2p_answer(data):
    """Relay P2P answer from receiver back to sender."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    emit("message", {"type": "p2p_answer", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("p2p_ice")
def handle_p2p_ice(data):
    """Relay ICE candidate between P2P transfer peers."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    emit("message", {"type": "p2p_ice", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("p2p_decline")
def handle_p2p_decline(data):
    """Relay transfer decline back to the sender."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    emit("message", {"type": "p2p_decline", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("call_invite")
def handle_call_invite(data):
    """Relay incoming call invite to recipient; inject server-verified caller identity."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    data["caller_id"]   = current_user.id
    data["caller_name"] = current_user.username
    emit("message", {"type": "call_invite", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("call_accept")
def handle_call_accept(data):
    """Relay WebRTC answer from callee back to caller."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    emit("message", {"type": "call_accept", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("call_decline")
def handle_call_decline(data):
    """Relay call decline to caller."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    emit("message", {"type": "call_decline", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("call_ice")
def handle_call_ice(data):
    """Relay ICE candidate between call peers."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    emit("message", {"type": "call_ice", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("call_end")
def handle_call_end(data):
    """Relay call end to the other party."""
    if not current_user.is_authenticated:
        return False
    if not isinstance(data, dict):
        return
    try:
        recipient_id = int(data.get("recipient_id"))
    except (TypeError, ValueError):
        return
    emit("message", {"type": "call_end", "payload": data}, to=f"user_{recipient_id}")


@socketio.on("connect")
def handle_connect():
    if not current_user.is_authenticated:
        return False
    uid = current_user.id
    join_room(f"user_{uid}")
    join_room("broadcast")
    _sid_to_uid[request.sid] = uid
    prev = _uid_conns.get(uid, 0)
    _uid_conns[uid] = prev + 1
    if prev == 0:
        # First connection for this user — tell everyone else they came online
        socketio.emit("message", {"type": "user_online", "payload": {"user_id": uid}},
                      room="broadcast", skip_sid=request.sid)
    # Tell the connecting client who is currently online
    emit("message", {"type": "online_users",
                     "payload": {"user_ids": [u for u, c in _uid_conns.items() if c > 0]}})


@socketio.on("disconnect")
def handle_disconnect():
    client_tiers.pop(request.sid, None)
    uid = _sid_to_uid.pop(request.sid, None)
    if uid is not None:
        count = max(_uid_conns.get(uid, 1) - 1, 0)
        if count == 0:
            _uid_conns.pop(uid, None)
            socketio.emit("message", {"type": "user_offline", "payload": {"user_id": uid}},
                          room="broadcast")
        else:
            _uid_conns[uid] = count


@socketio.on("client_tier")
def handle_client_tier(data):
    if not current_user.is_authenticated:
        return
    if not isinstance(data, dict):
        return
    tier = data.get("tier", "wifi_weak")
    if tier not in MEDIA_CONFIG:
        tier = "wifi_weak"
    client_tiers[request.sid] = {
        "tier": tier,
        "rtt": data.get("rtt", 50),
        "user_id": current_user.id,
    }
    c = MEDIA_CONFIG[tier]
    emit("message", {
        "type": "client_config",
        "payload": {
            "tier": tier,
            "video_chunk_size": c["video_chunk_size"],
            "photo_compress": c["photo_compress"],
            "photo_max_dim": c["photo_max_dim"],
            "photo_quality": c["photo_quality"],
        },
    })


@socketio.on("message")
def handle_socket_message(data):
    if not current_user.is_authenticated:
        return False

    if not isinstance(data, dict):
        emit("message", {"type": "error", "code": "PARSE_ERROR",
                         "message": "Invalid message format.", "requestId": ""})
        return

    request_id = str(data.get("requestId", ""))
    msg_type   = str(data.get("type", ""))
    payload    = data.get("payload") if isinstance(data.get("payload"), dict) else {}

    if msg_type != "send_message":
        emit("message", {"type": "error", "code": "UNKNOWN_TYPE",
                         "message": f"Unknown type: {msg_type!r}", "requestId": request_id})
        return

    if is_rate_limited(current_user.id):
        emit("message", {"type": "error", "code": "RATE_LIMITED",
                         "message": "Too many messages. Please slow down.",
                         "requestId": request_id})
        return

    ephemeral_pub        = str(payload.get("ephemeral_pub", "plain-text-prototype"))
    sock_iv              = str(payload.get("iv", "plain-text-prototype"))
    is_e2ee              = payload.get("is_e2ee") is True
    sender_copy          = payload.get("sender_copy") or None
    sender_ephemeral_pub = payload.get("sender_ephemeral_pub") or None
    sender_iv            = payload.get("sender_iv") or None

    message, error = build_message(
        current_user,
        str(payload.get("receiver_id", "")),
        str(payload.get("content", "")),
        ephemeral_pub=ephemeral_pub,
        msg_iv=sock_iv,
        is_e2ee=is_e2ee,
        sender_copy=sender_copy,
        sender_ephemeral_pub=sender_ephemeral_pub,
        sender_iv=sender_iv,
    )

    if error:
        emit("message", {"type": "error", "code": "INVALID_REQUEST",
                         "message": error, "requestId": request_id})
        return

    db.session.add(message)
    db.session.commit()
    emit_saved_message(message, request_id)


app = create_app()


def _cleanup_abandoned_uploads() -> None:
    """Remove chunk dirs older than 2 h and mark stale 'processing' records as 'failed'."""
    import datetime
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=2)
    for path in _TEMP_DIR.iterdir():
        if path.name.startswith("vid_") and path.is_dir():
            mtime = datetime.datetime.utcfromtimestamp(path.stat().st_mtime)
            if mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)

    stale_cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    with app.app_context():
        stale = FileRecord.query.filter_by(status="processing").all()
        changed = False
        for rec in stale:
            if rec.uploaded_at.replace(tzinfo=None) < stale_cutoff:
                rec.status = "failed"
                changed = True
        if changed:
            db.session.commit()


if _APSCHEDULER_AVAILABLE:
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(_cleanup_abandoned_uploads, "interval", minutes=30)
    _scheduler.start()


def _ensure_ssl_cert(cert_path: Path, key_path: Path) -> bool:
    """Generate a persistent self-signed TLS certificate if one doesn't exist yet.

    Tries the `cryptography` library first; falls back to the `openssl` CLI
    (available on MSYS2/Git Bash/Linux).  Includes localhost and the machine's
    LAN IP in the SAN so the browser warning only appears once per device.
    Returns True if a usable certificate is ready.
    """
    if cert_path.exists() and key_path.exists():
        return True

    import socket as _socket
    lan_ip: str | None = None
    lan_ips: list[str] = []
    try:
        # Collect all non-loopback IPv4 addresses across all interfaces
        for _info in _socket.getaddrinfo(_socket.gethostname(), None):
            _addr = _info[4][0]
            if _addr and not _addr.startswith("127.") and ":" not in _addr and _addr not in lan_ips:
                lan_ips.append(_addr)
        if lan_ips:
            lan_ip = lan_ips[0]
    except Exception:
        pass

    # ── Method 1: cryptography library ──────────────────────────────────────
    try:
        import ipaddress
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        san_entries: list = [x509.DNSName("localhost"),
                             x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
        for _ip in lan_ips:
            san_entries.append(x509.IPAddress(ipaddress.IPv4Address(_ip)))

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IntraComms LAN")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        _ssl_cert_success(cert_path)
        return True
    except ImportError:
        pass  # cryptography not available — try openssl CLI
    except Exception as exc:
        print(f"[IntraComms] cryptography error: {exc}")

    # ── Method 2: openssl CLI (MSYS2 / Git Bash / Linux) ───────────────────
    try:
        import tempfile
        san_val = "IP:127.0.0.1,DNS:localhost"
        for _ip in lan_ips:
            san_val += f",IP:{_ip}"
        cnf = (
            "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
            "[dn]\nCN=IntraComms LAN\n"
            f"[v3]\nsubjectAltName={san_val}\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as f:
            f.write(cnf)
            cnf_path = f.name
        result = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", str(key_path), "-out", str(cert_path),
             "-days", "3650", "-nodes", "-config", cnf_path],
            capture_output=True, text=True,
        )
        Path(cnf_path).unlink(missing_ok=True)
        if result.returncode == 0 and cert_path.exists():
            _ssl_cert_success(cert_path)
            return True
        print(f"[IntraComms] openssl failed: {result.stderr.strip()}")
    except FileNotFoundError:
        print("[IntraComms] openssl CLI not found.")
    except Exception as exc:
        print(f"[IntraComms] openssl error: {exc}")

    print("[IntraComms] Could not generate SSL certificate.")
    print("[IntraComms] Falling back to plain HTTP — E2EE will be disabled on non-localhost clients.")
    return False


def _ssl_cert_success(cert_path: Path) -> None:
    print(f"[IntraComms] TLS certificate ready → {cert_path}")
    print("[IntraComms] Access the app at  https://<LAN-IP>:5000")
    print("[IntraComms] Android: tap Advanced → Proceed (once per device to accept the cert)")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    _cert = BASE_DIR / "cert.pem"
    _key  = BASE_DIR / "key.pem"
    ssl_ok = _ensure_ssl_cert(_cert, _key)
    # eventlet (used by Flask-SocketIO) takes certfile/keyfile, not ssl_context
    ssl_kwargs = {"certfile": str(_cert), "keyfile": str(_key)} if ssl_ok else {}
    socketio.run(app, host="0.0.0.0", debug=debug_mode, use_reloader=debug_mode,
                 **ssl_kwargs)
