from datetime import datetime, timezone

from .database import db


ALLOWED_EXTENSIONS = {
    # Images
    "png", "jpg", "jpeg", "gif", "webp",
    # Video
    "mp4", "webm", "mov",
    # Audio
    "mp3", "ogg", "wav",
    # Documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    # Archives
    "zip", "tar", "gz",
}

MIME_CATEGORIES = {
    "image": {"image/jpeg", "image/png", "image/gif", "image/webp"},
    "video": {"video/mp4", "video/webm", "video/quicktime"},
    "audio": {"audio/mpeg", "audio/ogg", "audio/wav", "audio/webm"},
}

MAX_FILE_SIZE = 50 * 1024 * 1024


class FileRecord(db.Model):
    """
    Metadata record for a file uploaded to the IntraComms server.

    The actual file is stored on disk inside the uploads/ directory. The file
    on disk is AES-256 encrypted, so original bytes are never stored in plain
    form.
    """

    __tablename__ = "file_records"

    id = db.Column(db.Integer, primary_key=True)
    uploader_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    receiver_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True, index=True
    )
    original_filename = db.Column(db.String(256), nullable=False)
    stored_filename = db.Column(db.String(256), nullable=False, unique=True)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(128), nullable=True)
    ephemeral_pub = db.Column(db.Text, nullable=False)
    iv = db.Column(db.String(64), nullable=False)
    visibility = db.Column(db.String(16), nullable=False, default="shared")
    download_count = db.Column(db.Integer, nullable=False, default=0)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    uploaded_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True
    )
    deleted_at = db.Column(db.DateTime, nullable=True)

    # Media pipeline fields (populated after processing)
    status = db.Column(db.String(20), nullable=False, default="ready")
    # Values: 'processing' | 'ready' | 'failed'
    thumbnail_filename = db.Column(db.String(256), nullable=True)
    original_size = db.Column(db.BigInteger, nullable=True)
    processed_size = db.Column(db.BigInteger, nullable=True)
    upload_tier = db.Column(db.String(20), nullable=True)
    media_width = db.Column(db.Integer, nullable=True)
    media_height = db.Column(db.Integer, nullable=True)
    media_duration = db.Column(db.Float, nullable=True)

    # E2EE fields — populated for encrypted uploads
    is_e2ee = db.Column(db.Boolean, nullable=False, default=False)
    # "client_e2ee": encrypted before upload; "server_at_rest": encrypted after transcoding
    encryption_type = db.Column(db.String(32), nullable=True)
    file_iv = db.Column(db.String(64), nullable=True)        # AES-GCM IV for the blob
    sealed_key = db.Column(db.Text, nullable=True)           # file key sealed for recipient
    key_ephemeral_pub = db.Column(db.Text, nullable=True)    # ECIES ephemeral pub (recipient)
    key_iv = db.Column(db.String(64), nullable=True)         # ECIES IV (recipient)
    sender_sealed_key = db.Column(db.Text, nullable=True)    # file key sealed for sender
    sender_key_ephemeral = db.Column(db.Text, nullable=True) # ECIES ephemeral pub (sender)
    sender_key_iv = db.Column(db.String(64), nullable=True)  # ECIES IV (sender)
    encrypted_meta = db.Column(db.Text, nullable=True)       # filename/mime/size, AES-encrypted
    hint_category  = db.Column(db.String(16), nullable=True) # "image"/"video"/"audio"/"file" — E2EE category hint

    uploader = db.relationship(
        "User", foreign_keys=[uploader_id], back_populates="uploaded_files"
    )
    receiver = db.relationship("User", foreign_keys=[receiver_id])

    @staticmethod
    def is_allowed_extension(filename: str) -> bool:
        """Return True if the file extension is in the allowed set."""
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return ext in ALLOWED_EXTENSIONS

    @staticmethod
    def is_within_size_limit(size_bytes: int) -> bool:
        return size_bytes <= MAX_FILE_SIZE

    def increment_download(self) -> None:
        self.download_count += 1

    def media_category(self) -> str:
        """Return 'image', 'video', 'audio', or 'file' based on MIME type."""
        mime = (self.mime_type or "").lower()
        if mime.startswith("image/"):
            return "image"
        if mime.startswith("video/"):
            return "video"
        if mime.startswith("audio/"):
            return "audio"
        return "file"

    def soft_delete(self) -> None:
        """Mark as deleted without removing the DB record."""
        self.is_deleted = True
        self.deleted_at = datetime.now(timezone.utc)

    def file_size_human(self) -> str:
        """Return a human-readable file size string."""
        size = self.file_size
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "uploader_id": self.uploader_id,
            "uploader_username": self.uploader.username if self.uploader else None,
            "receiver_id": self.receiver_id,
            "original_filename": self.original_filename,
            "file_size": self.file_size,
            "file_size_human": self.file_size_human(),
            "mime_type": self.mime_type,
            "visibility": self.visibility,
            "download_count": self.download_count,
            "is_deleted": self.is_deleted,
            "uploaded_at": self.uploaded_at.isoformat(),
        }

    def __repr__(self) -> str:
        return (
            f"<FileRecord id={self.id} file={self.original_filename!r} "
            f"uploader={self.uploader_id}>"
        )
