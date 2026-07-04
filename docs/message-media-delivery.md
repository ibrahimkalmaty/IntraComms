# Message & Media Delivery System

## 1. Text Message Flow

### Primary path — WebSocket

1. User types and hits Enter (or clicks Send). The form's `submit` handler in `static/js/chat.js:590` checks if the socket is open.
2. If connected, `preventDefault()` stops the HTTP POST. `sendWs()` at line 524 sends:
   ```
   42["message", {"type":"send_message","payload":{"receiver_id":...,"content":...},"requestId":"..."}]
   ```
   The `42` prefix is raw Engine.IO v4 framing — `4` = Socket.IO packet, `2` = event. There is no `socket.io.js` library; the client implements the protocol by hand.
3. `@socketio.on("message")` in `server/server.py:978` receives this. It calls `build_message()` which validates the recipient and constructs a `Message` ORM object (currently with placeholder `"plain-text-prototype"` values for the AES fields — encryption is not yet implemented).
4. The message is saved to SQLite. `emit_saved_message()` at line 349 wraps it in a `{"type":"new_message","payload":{...}}` envelope and emits it over Socket.IO.
5. **Room routing:** Each user joins `user_{id}` and `"broadcast"` on WebSocket connect. A direct message goes to `user_{sender_id}` and `user_{receiver_id}`. A broadcast goes to `"broadcast"`. Both sender and receiver get the event in real time.
6. The client's `handlePacket()` at line 544 strips the `42` prefix, parses the JSON, and calls `dispatch()`. `dispatch()` routes `type === "new_message"` to `appendMessage()`, which builds the bubble HTML and injects it into the DOM.

### Fallback path — HTTP POST

If the socket is not open and no socket object exists, the form is allowed to submit normally as `POST /messages`. The route at `server.py:576` runs the same `build_message()` / `emit_saved_message()` pipeline, then redirects back to `/dashboard`.

### Offline buffer

If the socket exists but is reconnecting (e.g., between disconnect and backoff retry), the message is pushed to `messageQueue`. On reconnect, `flushQueue()` at line 536 drains the buffer in order.

---

## 2. WebSocket Protocol Details

The client connects to `/socket.io/?EIO=4&transport=websocket` (bypassing the Socket.IO JS library entirely). The handshake sequence:

| Server sends | Client responds | Meaning |
|---|---|---|
| `"0{...json...}"` | `"40"` | EIO open → Socket.IO connect |
| `"2"` | `"3"` | ping → pong (keepalive) |
| `"42[...]"` | (event data) | Socket.IO event carrying a typed envelope |

Exponential backoff reconnect: starts at 1 s, doubles on each close, caps at 30 s (`chat.js:36-37`).

---

## 3. Connection Tier & Adaptive Quality

Every 2 minutes, `measureConnection()` at `chat.js:44` fires a `GET /ping` (returns 204 immediately) and measures round-trip time. Combined with the `navigator.connection.downlink` API where available, it classifies the connection:

| Tier | RTT | Downlink |
|---|---|---|
| `wired` | < 5 ms | > 50 Mbps |
| `wifi_good` | < 20 ms | > 20 Mbps |
| `wifi_weak` | < 60 ms | > 5 Mbps |
| `slow` | anything else | — |

The tier is reported to the server via `42["client_tier", {tier, rtt, downMbps}]`. The server stores it in `client_tiers[sid]` keyed by Socket.IO session ID. When processing any upload, `get_tier_for_user()` at `server.py:90` picks the *worst* tier across all of that user's active sessions, then `cfg(user_id)` returns the matching `MEDIA_CONFIG` entry.

### MEDIA_CONFIG values per tier

| Setting | wired | wifi_good | wifi_weak | slow |
|---|---|---|---|---|
| Photo max dimension | 2560 px | 1920 px | 1280 px | 800 px |
| Photo WebP quality | 88 | 85 | 80 | 75 |
| Thumbnail size | 320 px | 240 px | 160 px | 120 px |
| Video scale | 1080p | 720p | 480p | 360p |
| Video CRF | 23 | 25 | 28 | 30 |
| Audio bitrate | 64k | 48k | 32k | 24k |
| Cache max-age | 7 days | 3 days | 7 days | 14 days |

---

## 4. File & Media Upload

### Images and other files (single-request upload)

1. User clicks the paperclip button → `fileInputEl.click()` → file picker.
2. `uploadFile()` at `chat.js:677` is called. Videos are redirected to `uploadVideoChunks()`. Everything else uses a single XHR `POST /upload` with `multipart/form-data`.
3. Upload progress updates the status bar in real time via XHR's `progress` event.
4. `POST /upload` (`server.py:621`) validates the file extension against `FileRecord.is_allowed_extension()`, checks the 50 MB limit, then runs the appropriate pipeline:

**Image pipeline** (`process_photo()` at `server.py:107`):
- Opens with Pillow, applies EXIF rotation via `ImageOps.exif_transpose`.
- Resizes to at most `photo_max_dim` × `photo_max_dim` (preserving aspect ratio).
- Converts transparency (RGBA/P/LA) to white-background RGB.
- Saves as WebP at `photo_quality` with `exif=b""` — strips all EXIF metadata at write time.
- Center-crops a square thumbnail at `photo_thumb_dim` pixels and saves it alongside.
- Output: `uploads/<uuid>.webp` and `uploads/<uuid>_thumb.webp`.

**Audio pipeline** (`process_audio()` at `server.py:147`):
- Calls `ffprobe` to measure duration.
- Calls `ffmpeg` to re-encode as Opus OGG at the tier's `audio_bitrate`.
- Output: `uploads/<uuid>.ogg`.

**Other files:** saved as-is under a UUID filename, no processing.

5. A `FileRecord` row is created with `status="ready"`, then a `Message` row links to it via `file_record_id`. `emit_saved_message()` fires immediately — the receiver sees the file right away.

### Videos (chunked upload + background transcode)

Videos cannot fit in a single HTTP request for large files and require FFmpeg transcoding which takes time. The flow is:

1. `uploadVideoChunks()` at `chat.js:725` slices the file into chunks of `UPLOAD_CONFIG.video_chunk_size` bytes (default 5 MB for wifi_good, server-configured per tier).
2. Chunks are sent sequentially to `POST /upload/video/chunk` with a shared `media_id` UUID, `chunk_index`, and `total_chunks`.
3. Each chunk is saved to a temp directory `%TEMP%/vid_{media_id}/00001`, `00002`, etc.
4. When the server receives the last chunk (received count == total):
   - Creates a `FileRecord` with `status="processing"` and a `Message` immediately.
   - Calls `emit_saved_message()` — the receiver sees a spinner/poster placeholder right away.
   - Spawns `_transcode_video()` in a **daemon thread** (non-blocking, `server.py:170`).
5. The background thread:
   - Assembles all chunks into one raw file.
   - Grabs a poster frame at the 1-second mark via `ffmpeg -vframes 1`.
   - Probes duration with `ffprobe`.
   - Transcodes to H.264/AAC MP4 with `-movflags +faststart` (enables streaming before full download). Scale and CRF are tier-dependent.
6. On success: updates `FileRecord.status = "ready"` in the DB, emits `{"type":"media_ready","payload":{url,thumb_url,duration}}` to the same rooms.
7. On failure: sets `status="failed"`, emits `{"type":"media_failed","payload":{media_id,error}}`.

**Client handling:**
- `dispatch()` type `media_ready` (`chat.js:468`): finds the spinner wrapper by `data-media-id`, builds a real `<video>` element via `buildMediaHtml()`, and replaces the placeholder in-place.
- `dispatch()` type `media_failed` (`chat.js:506`): shows a "⚠ Media unavailable" error in the bubble.

---

## 5. Media Serving & Access Control

### `GET /uploads/<file_id>` (`server.py:867`)

- Checks `_user_can_access()`: caller must be the uploader, the named recipient, or the file must be `visibility="broadcast"`.
- Returns `202` if still `status="processing"`, `410` if `status="failed"`, `404` if deleted.
- Sets `Cache-Control: private, max-age=N` where `N` is tier-dependent (see table above).
- Images, video, and audio are served inline; all other file types get `Content-Disposition: attachment`.
- Counts unique downloads per `(user_id, file_id)` pair in memory — one DB write per unique pair, not per request.

### `GET /uploads/<file_id>/thumb` (`server.py:906`)

- Same access control.
- Returns the WebP or JPEG thumbnail with a fixed 7-day cache header.

### Thumbnail-first image display

The JS client renders images with the thumbnail loaded first:

```html
<img src="/uploads/5/thumb" data-full="/uploads/5" class="media-img thumb-preview">
```

Clicking triggers `expandPhoto()` (`chat.js:184`): loads the full image in a hidden `Image()` object first, then swaps `img.src` only after it is fully loaded. State is tracked via a CSS class (`expanded`) so repeat clicks are ignored. A wrapping `<a href="/uploads/5" target="_blank">` lets the user right-click to open or download the full image directly.

---

## 6. Delete Flow

1. Sender clicks the trash icon on their own message. Event delegation on `#message-list` catches `.msg-del-btn` clicks (`chat.js:797`). The button is immediately disabled to prevent double-sends.
2. `fetch("/messages/<id>/delete", {method:"POST"})` — if the response is not OK, the button is re-enabled.
3. Server `delete_message()` (`server.py:594`):
   - Verifies the caller is the sender (returns 403 otherwise).
   - Calls `msg.soft_delete()` — sets `is_deleted=True`, records `deleted_at` timestamp.
   - If the message has a linked `FileRecord`, that is also soft-deleted.
   - Commits to DB.
4. Emits `{"type":"message_deleted","payload":{"message_id":N}}` to the same rooms as the original message — both sender and receiver receive it simultaneously.
5. Client `dispatch()` type `message_deleted` (`chat.js:490`): finds the `article[data-message-id="N"]`, replaces the bubble's content with `<p class="message-deleted">Message deleted</p>`, removes the delete button, and strips the `media-bubble` CSS class.

The row stays in the database (soft-delete preserves conversation history). The file on disk is not immediately removed; a cleanup job would require APScheduler (installed but not yet wired up).

---

## 7. Page Load vs. Real-time

The `/dashboard` route loads the last **200 messages** involving the current user (their DMs + all broadcasts) and renders them server-side as Jinja2 `<article>` elements with `data-message-type`, `data-sender-id`, `data-receiver-id` attributes.

Switching conversations calls `filterMessages()` (`chat.js:252`) which hides/shows articles by matching those data attributes against `activeChatId`. **No HTTP request is made when switching conversations** — it is entirely client-side DOM filtering.

New messages arriving over WebSocket are handled by `appendMessage()` (`chat.js:375`), which constructs the same `<article>` structure dynamically and inserts it into the live list.

The sidebar conversation previews (`#preview-{chatId}` and `#preview-time-{chatId}`) are populated on page load by `initPreviews()` and updated on each new message by `updatePreview()`.
