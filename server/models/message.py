from datetime import datetime, timezone

from .database import db


class Message(db.Model):
    """
    Represents an encrypted message between two users, or a broadcast sent to
    all users on the network.

    Encryption model (ECIES / AES-256-GCM):
        - content       : AES-256-GCM ciphertext (base64). Never plaintext for E2EE messages.
        - ephemeral_pub : The sender's per-message ephemeral ECDH public key (base64 SPKI).
                          The recipient uses DH(their_private, ephemeral_pub) to derive the
                          AES key. The AES key itself is NEVER stored anywhere.
        - iv            : AES-GCM nonce (12 random bytes, base64).
        - is_e2ee       : True for encrypted direct messages; False for broadcast.

    Message types:
        direct    - private, one sender to one receiver
        broadcast - one sender to all active users (always plaintext — public by nature)
    """

    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    receiver_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True, index=True
    )
    content = db.Column(db.Text, nullable=False)
    ephemeral_pub = db.Column(db.Text, nullable=False)
    iv = db.Column(db.String(64), nullable=False)
    # Sender's own copy — ciphertext encrypted with the sender's public key so
    # they can read back their own sent messages without the recipient's key.
    sender_copy          = db.Column(db.Text, nullable=True)
    sender_ephemeral_pub = db.Column(db.Text, nullable=True)
    sender_iv            = db.Column(db.String(64), nullable=True)
    message_type = db.Column(db.String(16), nullable=False, default="direct")
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    is_e2ee = db.Column(db.Boolean, nullable=False, default=False)
    file_record_id = db.Column(db.Integer, db.ForeignKey("file_records.id"), nullable=True)
    timestamp = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True
    )

    sender = db.relationship(
        "User", foreign_keys=[sender_id], back_populates="sent_messages"
    )
    receiver = db.relationship(
        "User", foreign_keys=[receiver_id], back_populates="received_messages"
    )
    file_record = db.relationship("FileRecord", foreign_keys=[file_record_id])

    def is_broadcast(self) -> bool:
        return self.message_type == "broadcast"

    def mark_as_read(self) -> None:
        self.is_read = True

    def soft_delete(self) -> None:
        self.is_deleted = True
        self.deleted_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        """Return a safe dict. Content remains encrypted for client-side use."""
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "sender_username": self.sender.username if self.sender else None,
            "receiver_id": self.receiver_id,
            "content": self.content,
            "ephemeral_pub": self.ephemeral_pub,
            "iv": self.iv,
            "message_type": self.message_type,
            "is_read": self.is_read,
            "timestamp": self.timestamp.isoformat(),
        }

    def __repr__(self) -> str:
        return (
            f"<Message id={self.id} type={self.message_type!r} "
            f"from={self.sender_id} to={self.receiver_id}>"
        )
