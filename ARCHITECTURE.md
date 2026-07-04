# IntraComms — Complete Architecture & Security Reference

---

## 1. System Overview

```
Browser A ──WebSocket──┐                ┌──WebSocket── Browser B
                       │  Flask/SIO     │
                       └──► server.py ◄─┘
                              │
                         SQLite DB  +  uploads/ (disk)
                              │
                    (Audio/video only)
                         FFmpeg / Pillow

P2P paths bypass the server entirely:
Browser A ──────────────────────────────────────────► Browser B
              WebRTC DataChannel (large files)
              WebRTC MediaStream  (voice calls)
```

### Stack

| Layer | Tech |
|---|---|
| Server | Python 3.12, Flask, Flask-SocketIO (eventlet) |
| Transport | HTTP + WebSocket (EIO4 protocol, raw — no socket.io.js client) |
| Database | SQLite via SQLAlchemy ORM |
| Crypto (server) | `cryptography` 44 — HKDF-SHA256, AES-256-GCM, ECDH P-256 |
| Crypto (browser) | Web Crypto API — SubtleCrypto, same primitives |
| Media processing | Pillow (images), FFmpeg (video/audio) |
| Real-time P2P | WebRTC (`RTCPeerConnection` + `RTCDataChannel` / `MediaStream`) |

---

## 2. Connection & Signalling Protocol

### 2.1 WebSocket Framing (EIO4, no library)

```
Server → Client:  "0"        EIO open
Client → Server:  "40"       Socket.IO connect
Server → Client:  "2"        ping
Client → Server:  "3"        pong
Server → Client:  "42[\"message\", {...}]"   event
Client → Server:  "42[\"event\", {...}]"     event
```

Every message flows through one envelope format:

```json
{ "type": "event_name", "payload": {...}, "requestId": "..." }
```

`requestId` correlates client sends to echoed receipts. All server-side Socket.IO events are emitted as `"message"` with a typed `type` field — never raw named events (except legacy `call_*` handlers that accept named events and re-wrap them).

### 2.2 Rooms

| Room | Who joins | Used for |
|---|---|---|
| `user_{id}` | Every authenticated session | DM delivery, call signalling, file notifications |
| `"broadcast"` | Everyone | Broadcast messages, `user_joined`, `media_ready` |

---

## 3. Text Messaging Protocol

### 3.1 Happy path (WebSocket, E2EE DM)

```
Client A                        Server                         Client B
   │                               │                               │
   │  42["message", {              │                               │
   │    type: "send_message",      │                               │
   │    payload: {                 │                               │
   │      receiver_id: B_id,       │                               │
   │      content: <AES-GCM ct>,   │                               │
   │      ephemeral_pub: <spki>,   │                               │
   │      iv: <b64>,               │                               │
   │      sender_copy: <ct>,       │                               │
   │      sender_ephemeral_pub,    │                               │
   │      sender_iv,               │                               │
   │      is_e2ee: true            │                               │
   │    }                          │                               │
   │  }]                           │                               │
   │──────────────────────────────►│                               │
   │                               │  build_message() → DB save   │
   │                               │  emit_saved_message()         │
   │                               │──────────────────────────────►│
   │◄──────────────────────────────│  (echo to sender room too)    │
   │  type:"new_message"           │                               │
```

**Offline buffer:** if `socket.readyState !== OPEN`, the message is pushed into a JS-side `messageQueue[]` and flushed on reconnect.

**Rate limiting:** 30 messages/minute per user (server-side, per 60-second window).

### 3.2 Broadcast path

`receiver_id = "broadcast"` → no encryption, stored with `ephemeral_pub = "plain-text-prototype"`, emitted to `"broadcast"` room.

### 3.3 HTTP fallback

`POST /messages` → `build_message()` → DB → `emit_saved_message()` → redirect. Only triggers if the WebSocket path is blocked.

### 3.4 Message deletion

`POST /messages/<id>/delete` — soft delete only (sets `is_deleted = true`, clears ciphertext). Server emits `type: "message_deleted"` to both parties' rooms. Associated `FileRecord` is also soft-deleted.

---

## 4. Voice Messaging Protocol

Voice messages reuse the **entire file E2EE pipeline** — no new server routes.

```
Browser (sender)
  1. MediaRecorder → Opus chunks (200ms slices)
  2. Blob → File("voice-message-<ts>.webm", "audio/webm")
  3. Measure duration (Date.now() delta)
  4. AES-256-GCM encrypt file bytes (new random key)
  5. ECIES-seal file key for recipient + sender own-copy
  6. AES-GCM encrypt meta = {name, type, size, duration} with file key
  7. POST /upload/e2ee  (hint_category="audio")
     ↓
Server stores opaque .enc blob + key material → emits new_message
     ↓
Browser (recipient) sees playback bubble
  1. Click play → GET /uploads/<id>/meta  (server returns correct sealed key copy)
  2. GET /uploads/<id>/blob  (encrypted bytes)
  3. ECIES-unseal → AES key
  4. AES-256-GCM decrypt blob → audio bytes
  5. URL.createObjectURL → Audio.play()
```

The server never sees plaintext audio. The file never leaves the browser unencrypted. `hint_category = "audio"` is the only server-visible signal that the blob is a voice message (used for UI routing only — it carries no audio content).

---

## 5. Images Protocol

### 5.1 Plaintext (broadcast or pre-key user)

```
POST /upload
  → Pillow: EXIF strip, resize to tier max_dim, re-encode WebP
  → generate _thumb.webp (square crop, small)
  → FileRecord(status="ready", mime="image/webp")
  → Message → emit new_message
  → <img src="/uploads/<id>"> + click-to-expand full size
```

**Tier-adaptive dimensions:**

| Tier | Max dim | Thumb dim | Quality |
|---|---|---|---|
| wired | 2560 | 320 | 88 |
| wifi_good | 1920 | 240 | 85 |
| wifi_weak | 1280 | 160 | 80 |
| slow | 800 | 120 | 75 |

### 5.2 E2EE image (DM with both keys registered)

```
Browser:
  1. canvas.toBlob() → WebP compress (tier quality, max 1920px)
  2. AES-256-GCM encrypt → encrypted blob
  3. ECIES-seal key for recipient + sender
  4. POST /upload/e2ee  (hint_category="image", data-auto-decrypt="1")

Server: stores opaque blob, emits new_message with hint_category

Recipient auto-decrypts on message load:
  GET /meta + GET /blob → decrypt → <img> inline
```

Server never processes an E2EE image; Pillow never runs on it.

---

## 6. Video Protocol

```
Browser:
  1. File split into chunks (tier-adaptive: 1–20 MB each)
  2. POST /upload/video/chunk  (repeating, with retry/backoff)
  3. All chunks saved to temp dir vid_<media_id>/

Server (on last chunk):
  1. Assemble chunks → raw file
  2. emit new_message  (status="processing", spinner shown)
  3. Background thread → FFmpeg:
       - extract 1-frame thumbnail at t=1s (320px wide)
       - transcode: H.264 + AAC, tier-adaptive CRF/scale/preset
       - +faststart flag (streaming-ready)
  4. If DM + both pubkeys exist:
       encrypt_file_at_rest() → AES-256-GCM + ECIES-sealed key
       original plaintext: securely deleted (overwrite zeros then unlink)
  5. FileRecord updated: status="ready", media_duration, processed_size
  6. emit media_ready → client swaps spinner for <video> player
```

**Video tiers:**

| Tier | Chunk | CRF | Scale | Preset |
|---|---|---|---|---|
| wired | 20 MB | 23 | 1080p | fast |
| wifi_good | 5 MB | 25 | 720p | fast |
| wifi_weak | 2 MB | 28 | 480p | veryfast |
| slow | 1 MB | 30 | 360p | ultrafast |

---

## 7. Documents & Small Files Protocol

### 7.1 Plaintext (≤ 50 MB, broadcast)

```
POST /upload → extension allow-list check → save raw → FileRecord → Message
Serve: GET /uploads/<id>  (as_attachment=True, Cache-Control with tier max_age)
```

Allowed extensions: `png jpg jpeg gif webp mp4 webm mov mp3 ogg wav pdf doc docx xls xlsx ppt pptx txt csv zip tar gz`

### 7.2 E2EE (DM, ≤ 50 MB)

```
Browser:
  AES-256-GCM encrypt → POST /upload/e2ee  (hint_category="file")

Recipient clicks lock icon:
  GET /meta + GET /blob → decrypt → auto-download via <a download>
```

The server stores `[encrypted]` as the `original_filename` when no name is sent, but the real filename is inside `encrypted_meta`.

---

## 8. Large File P2P Protocol (≥ 100 MB)

Server is purely a **signalling relay** — no file bytes ever hit it.

```
Sender                          Server (relay only)              Recipient
  │                                     │                             │
  │  generate AES-256-GCM key           │                             │
  │  ECIES-seal key for recipient       │                             │
  │  RTCPeerConnection.createOffer()    │                             │
  │──p2p_offer ──────────────────────►  │──────────────────────────►  │
  │  {offer, sealed_key, file metadata} │                             │
  │                                     │  E2EE.decryptRaw()          │
  │                                     │  importKey(raw) → fileKey   │
  │                                     │  createAnswer()             │
  │  ◄─────────────────────────────────  │◄──────── p2p_answer ──────  │
  │  setRemoteDescription(answer)       │                             │
  │  ◄─────── p2p_ice ─────────────────►│◄───── p2p_ice ────────────  │
  │                                     │                             │
  │  ◄═══ WebRTC DataChannel open ══════════════════════════════════►  │
  │                                     │                             │
  │  for each 64KB chunk:               │                             │
  │    iv = getRandomValues(12)         │                             │
  │    AES-GCM encrypt(chunk, iv)       │                             │
  │    send [iv | ciphertext]           │                             │
  │──────────────────────────────────────────────────────────────────►│
  │                                     │                 decrypt each chunk
  │  send "done"                        │                 assemble Blob
  │──────────────────────────────────────────────────────────────────►│
  │                                     │                 auto-download
```

**Flow control:** sender checks `dc.bufferedAmount > 4 MB` every 10ms before sending the next chunk to avoid overwhelming the DataChannel buffer.

If recipient is offline or declines: `p2p_decline` → `cancelTransfer()` (closes PC). Files ≥ 100 MB to broadcast recipients are rejected outright with an error message.

---

## 9. Voice Call Protocol

Server is a **signalling relay only** — no audio bytes touch it. Audio is Opus-encoded, DTLS/SRTP encrypted, browser-to-browser.

```
State machine:  idle → calling → ringing → in_call → ended → idle

Caller                       Server (relay)                    Callee
  │                               │                               │
  │  getUserMedia() → mic stream  │                               │
  │  RTCPeerConnection + addTrack │                               │
  │  createOffer → setLocal       │                               │
  │──call_invite ────────────────►│──────────────────────────────►│
  │  {call_id, offer SDP}         │  server injects caller_name   │  state: ringing
  │                               │                               │  ringtone plays
  │                               │                               │  [accept click]
  │                               │                               │  getUserMedia()
  │                               │                               │  createPC + addTrack
  │                               │                               │  setRemoteDesc(offer)
  │                               │                               │  drainIceQueue()
  │                               │                               │  createAnswer → setLocal
  │  ◄───────────────────────────  │◄───────── call_accept ──────  │
  │  setRemoteDesc(answer)        │                               │
  │  drainIceQueue()              │                               │
  │  state: in_call               │                               │  state: in_call
  │  ◄──── call_ice ─────────────►│◄──── call_ice ───────────────►│  (trickle ICE, both directions)
  │                               │                               │
  │  ◄══ DTLS/SRTP audio stream ═══════════════════════════════►   │
  │                               │                               │
  │──call_end ───────────────────►│──────────────────────────────►│
```

**ICE candidate queue:** Candidates from the caller arrive while the callee's `RTCPeerConnection` doesn't exist yet (still on "ringing" screen). They are queued in `_iceCandidateQueue[]` and drained after `setRemoteDescription()` — this is the fix for the "connected but no audio" symptom where all ICE paths were silently dropped.

**Connection failure:** `pc.onconnectionstatechange` → `"failed"` or `"disconnected"` auto-calls `endCall()`.

---

## 10. Security Architecture

### 10.1 Identity & Key Infrastructure

```
Per-user identity:
  Private key  — ECDH P-256, non-extractable CryptoKey, stored as JWK in localStorage
  Public key   — SPKI base64, registered at POST /api/me/pubkey, stored in users.public_key

The private key NEVER leaves the browser.
The server stores only the public key.
Key fingerprint verification is manual (safety-number style, shown in chat header).
```

### 10.2 Text Message Encryption (ECIES + AES-256-GCM)

```
For each message:
  1. Generate ephemeral ECDH P-256 keypair (discarded after this message)
  2. DH(ephemeral_private, recipient_public) → 32-byte shared secret
  3. SubtleCrypto deriveKey(ECDH) → non-extractable AES-256-GCM key
     (effectively HKDF via SubtleCrypto's ECDH derivation)
  4. iv = getRandomValues(12)
  5. AES-GCM.encrypt(message_bytes, key, iv) → ciphertext

Stored on server per message:
  content            = ciphertext (base64)   ← for recipient
  ephemeral_pub      = ephemeral_pub SPKI    ← for recipient to derive same key
  iv                 = nonce                 ← for recipient
  sender_copy        = ciphertext encrypted with SENDER's own pubkey
  sender_ephemeral_pub / sender_iv           ← for sender to read their own messages

Server cannot decrypt any DM. It stores two opaque ciphertexts + ephemeral pubkeys.
Broadcast messages are always plaintext (public by nature — no per-recipient E2EE possible).
```

### 10.3 File Encryption — Two Paths

**Path A: client_e2ee** (DM files < 100 MB, voice messages, documents)

```
Browser:
  fileKey = AES-256-GCM random 256-bit key
  fileIv  = getRandomValues(12)
  ciphertext = AES-GCM.encrypt(file_bytes, fileKey, fileIv)

  For recipient:
    ECIES-seal(fileKey, recipient_pubkey) → {sealed, eph_pub, iv}
  For sender self-read:
    ECIES-seal(fileKey, sender_pubkey) → {sender_sealed, sender_eph_pub, sender_iv}

  encrypted_meta = AES-GCM.encrypt(
    JSON{name, type, size, duration?},
    fileKey,            ← same key as blob
    metaIv
  )

POST /upload/e2ee → server stores opaque blob + key material
                   server NEVER has fileKey
```

**Path B: server_at_rest** (videos after transcoding, when both pubkeys exist)

```
Server (Python, cryptography lib):
  fileKey = os.urandom(32)  → AESGCM(fileKey).encrypt(fileIv, plaintext)
  plaintext securely deleted (zero-overwrite + unlink)

  HKDF-SHA256 + ECDH P-256:
    _seal_file_key(fileKey, recipient_pubkey)  → {sealed, eph_pub, iv}
    _seal_file_key(fileKey, sender_pubkey)     → sender copy

  Server has fileKey in memory only during encryption — never persisted
```

**Key delivery** — `/uploads/<id>/meta` returns the correct sealed copy based on `is_sender`:

```python
"sealed_key":        sender_sealed_key    if is_sender else sealed_key
"key_ephemeral_pub": sender_key_ephemeral if is_sender else key_ephemeral_pub
```

### 10.4 P2P Large File Security

```
1. fileKey = AES-256-GCM random 256-bit key  (browser)
2. ECIES-seal(fileKey, recipient_pubkey) → signalled via server in p2p_offer
3. Recipient: E2EE.decryptRaw(key_ephem_pub, key_iv, sealed_key) → fileKey
4. Each 64 KB chunk:
     chunkIv = getRandomValues(12)
     wire packet = [12-byte IV | AES-GCM ciphertext]
5. DataChannel streams authenticated-encrypted chunks

Server sees: offer SDP, answer SDP, ICE candidates, sealed key material
Server never sees: file bytes, fileKey plaintext
```

### 10.5 Voice Call Security

```
WebRTC handles all crypto automatically:
  - DTLS 1.2/1.3 for key exchange (certificate fingerprint checked in SDP)
  - SRTP (AES-128-CM or AES-256-CM) for media encryption
  - SRTCP for RTCP control packets

Server sees: SDP offer/answer, ICE candidates, call control signals
Server never sees: audio samples, encryption keys

Call signalling is NOT end-to-end encrypted (relay is trusted — on-LAN server).
Caller identity is server-injected (prevents spoofing):
  data["caller_id"]   = current_user.id       ← from Flask session
  data["caller_name"] = current_user.username  ← from DB, not from client
```

### 10.6 Voice Message Security

Same as **client_e2ee** file path. Additionally:

- `hint_category = "audio"` is the only server-visible metadata — it reveals "this message contains audio" but nothing about content
- `original_filename` stored as `voice-message-<timestamp>.webm` (reveals timestamp and format)
- Real filename, MIME type, file size, and duration are inside `encrypted_meta` — only decryptable by the recipient and sender

### 10.7 Authentication & Session Security

```
Registration:
  Password: werkzeug PBKDF2-SHA256 (salted, stretched)
  First registered user → auto-promoted to admin
  Public key registered post-login via POST /api/me/pubkey

Session:
  Flask-Login + server-side session cookie (SECRET_KEY)
  All routes: @login_required
  WebSocket: current_user checked in every socket handler (return False if not authenticated)

Authorization checks:
  File access:    uploader_id == current_user.id
               OR receiver_id == current_user.id
               OR visibility == "broadcast"
  Message delete: sender_id == current_user.id only
  Admin:          role == "admin" checked via require_admin()
  Recipient validation: receiver must be active, not self, must exist
```

### 10.8 Transport Security

```
LAN deployment assumption:
  HTTP (not HTTPS) is the default — WebCrypto SubtleCrypto requires secure context
  → Must be served over HTTPS or localhost for encryption to function
  → When HTTP is used, E2EE is disabled and messages fall back to plaintext

Rate limiting:
  30 messages/minute per user (server-side, per-minute sliding window)
  All upload routes also rate-limited

File validation:
  Extension allow-list (ALLOWED_EXTENSIONS set in file_record.py)
  MAX_CONTENT_LENGTH = 50 MB (Flask-level hard rejection before route handler)
  werkzeug.utils.secure_filename() on all uploaded names
  MIME type from Content-Type header, falling back to mimetypes.guess_type()

E2EE upload enforcements:
  Broadcast receiver rejected (E2EE requires one recipient)
  Receiver must be active, not self
  stored_filename = secrets.token_hex(32) + ".enc"  (unguessable on-disk name)
  hint_category validated against allow-list {"image", "video", "audio", "file"}
```

### 10.9 Server-Side Secrets — What the Server Knows

| Data | What server stores | Can server read it? |
|---|---|---|
| DM text | AES-GCM ciphertext + ephemeral pubkey | No |
| Sender's own copy | Separate ciphertext + ephemeral pubkey | No |
| E2EE file blob | Opaque encrypted bytes | No |
| File key | ECIES-sealed ciphertext (sealed with user's pubkey) | No |
| File metadata | AES-GCM ciphertext (key = file key) | No |
| `hint_category` | Plaintext: `"image"/"audio"/"video"/"file"` | Yes — reveals media type only |
| `original_filename` | Plaintext for non-E2EE; `[encrypted]` for E2EE | Yes for non-E2EE only |
| User pubkeys | SPKI base64 | Yes — public by design |
| Passwords | PBKDF2-SHA256 hash | No |
| Broadcast messages | Plaintext | Yes — public by design |
| Video (post-transcode) | AES-encrypted blob, key ECIES-sealed | No (plaintext in memory during transcode only) |
| Call audio | Never received | N/A |
| P2P file bytes | Never received | N/A |

---

