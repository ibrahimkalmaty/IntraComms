from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .database import db


class User(UserMixin, db.Model):
    """
    Represents a registered user on the IntraComms system.

    Roles:
        admin - can manage users, view all messages, delete files
        user  - standard access: messaging and file sharing

    Encryption:
        Each user gets an RSA public key stored here. The matching private key
        is generated client-side and never sent to or stored on the server.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="user")
    public_key = db.Column(db.Text, nullable=True)
    encrypted_priv_key = db.Column(db.Text, nullable=True)
    key_salt = db.Column(db.String(32), nullable=True)
    avatar_filename = db.Column(db.String(256), nullable=True)
    avatar_thumb_filename = db.Column(db.String(256), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    last_seen = db.Column(db.DateTime, nullable=True)

    sent_messages = db.relationship(
        "Message",
        foreign_keys="Message.sender_id",
        back_populates="sender",
        lazy="dynamic",
    )
    received_messages = db.relationship(
        "Message",
        foreign_keys="Message.receiver_id",
        back_populates="receiver",
        lazy="dynamic",
    )
    uploaded_files = db.relationship(
        "FileRecord",
        foreign_keys="FileRecord.uploader_id",
        back_populates="uploader",
        lazy="dynamic",
    )

    def set_password(self, plain_password: str) -> None:
        """Hash and store a password. Never store plain text."""
        self.password_hash = generate_password_hash(plain_password)

    def check_password(self, plain_password: str) -> bool:
        """Return True if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, plain_password)

    def is_admin(self) -> bool:
        return self.role == "admin"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"
