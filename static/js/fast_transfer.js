// fast_transfer.js
// ─────────────────────────────────────────────────────────────────────
// High-speed encrypted file transfer over parallel TCP through the server.
// Replaces the WebRTC DataChannel path (p2p_transfer.js).
//
// Why this is faster/more reliable than WebRTC on a LAN:
//   WebRTC DataChannel rides SCTP, whose congestion control is tuned for
//   the lossy public internet and backs off on any queue buildup. It also
//   needs ICE to find a working host-candidate path — which often fails or
//   degrades when one peer is on wired LAN and the other on WiFi (different
//   subnets / AP client-isolation). The Flask server is the one host BOTH
//   clients are already connected to, so routing ciphertext through it over
//   plain TCP sidesteps all of that.
//
// Design — store-and-forward (NOT a live streaming pipe):
//   The server runs eventlet WITHOUT monkey-patching, so a request that
//   blocks waiting for another request would freeze the whole server. We
//   therefore never block: the sender POSTs each finished encrypted shard
//   to a temp file; the receiver GETs finished shards (retrying while a
//   shard is still uploading). This mirrors the existing /upload routes.
//
// E2EE: the per-transfer AES-256-GCM key is ECIES-sealed to the recipient
//   and travels over the WebSocket only. The filename/type/size live in an
//   encrypted metadata blob. The server sees ciphertext shards and nothing
//   else — it cannot decrypt, nor read the filename.
//
// Public API (mirrors the old P2PTransfer so chat.js wiring is unchanged):
//   FastTransfer.setSocketSend(fn)                 fn(event, data)
//   FastTransfer.send(file, recipientId, pubKeyB64) → Promise<transferId>
//   FastTransfer.handleOffer(payload, privateKey)
//   FastTransfer.onIncoming(fn)                    fn(transferId, {name,size,type})
//   FastTransfer.accept(transferId)
//   FastTransfer.decline(transferId)
//   FastTransfer.onProgress(transferId, fn)        fn(bytes, total)
//   FastTransfer.onComplete(transferId, fn)        fn(filename, size, elapsed)
//   FastTransfer.onError(transferId, fn)           fn(error)
// ─────────────────────────────────────────────────────────────────────

const FastTransfer = (() => {

  // ── Tuning ────────────────────────────────────────────────────────
  // Each shard is encrypted as one AES-GCM buffer and POSTed as one
  // request, so a shard must stay under the server's MAX_CONTENT_LENGTH
  // (50 MB). 32 MB leaves head-room for the 12 B IV + 16 B tag.
  const SHARD_MAX   = 32 * 1024 * 1024;   // max bytes of plaintext per shard
  const MAX_SHARDS  = 16;                  // server caps n_shards at 16
  const MAX_FILE    = SHARD_MAX * MAX_SHARDS;  // 512 MB hard ceiling
  const CONCURRENCY = 4;                    // parallel shard uploads/downloads
  const GET_RETRY_MS = 200;                 // poll interval while shard uploads
  const GET_RETRY_MAX = 900;                // ×200ms = 3 min max wait per shard

  let _socketSend   = null;
  const _pending    = new Map();   // transferId → receiver pending state
  const _onProgress = new Map();
  const _onComplete = new Map();
  const _onError    = new Map();
  let   _onIncoming = null;

  function setSocketSend(fn)  { _socketSend  = fn; }
  function onProgress(id, fn) { _onProgress.set(id, fn); }
  function onComplete(id, fn) { _onComplete.set(id, fn); }
  function onError(id, fn)    { _onError.set(id, fn); }
  function onIncoming(fn)     { _onIncoming  = fn; }

  // Bounded-concurrency map: runs `worker` over items, ≤ limit at once.
  // Keeps peak memory bounded regardless of shard count.
  async function _pool(items, limit, worker) {
    const out = new Array(items.length);
    let next = 0;
    async function run() {
      while (next < items.length) {
        const i = next++;
        out[i] = await worker(items[i], i);
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(limit, items.length) }, run)
    );
    return out;
  }

  // ════════════════════════════════════════════════════════════════
  // SENDER
  // ════════════════════════════════════════════════════════════════

  async function send(file, recipientId, recipientPubKeyB64) {
    if (file.size > MAX_FILE) {
      throw new Error("File too large — max " + (MAX_FILE / 1048576) + " MB.");
    }
    const transferId = crypto.randomUUID();   // [0-9a-f-], server validates
    const startTime  = Date.now();

    // Per-transfer AES-256-GCM key, sealed to the recipient (ECIES)
    const fileKey    = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const fileKeyRaw = await crypto.subtle.exportKey("raw", fileKey);
    const sealed     = await _sealKey(fileKeyRaw, recipientPubKeyB64);

    // Encrypted metadata — server never sees the filename
    const metaIv  = crypto.getRandomValues(new Uint8Array(12));
    const metaEnc = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: metaIv }, fileKey,
      new TextEncoder().encode(JSON.stringify({
        name: file.name, type: file.type, size: file.size,
      }))
    );

    const shards = _computeShards(file.size);

    // Tell the server to register the transfer and relay the offer
    _socketSend("transfer_offer", {
      transfer_id:   transferId,
      recipient_id:  recipientId,
      n_shards:      shards.length,
      file_size:     file.size,
      sealed_key:    sealed.encryptedKey,
      key_ephem_pub: sealed.ephemeralPub,
      key_iv:        sealed.iv,
      meta_iv:       _b64(metaIv),
      meta_enc:      _b64(metaEnc),
    });

    // Upload in the background and return the id NOW, so the caller can
    // register onProgress/onComplete before the first shard finishes.
    _uploadShards(transferId, recipientId, file, fileKey, shards, startTime);
    return transferId;
  }

  // Upload shards immediately (bounded concurrency) — we don't wait for the
  // receiver to accept, so the bytes are already staged on the server by the
  // time they click "accept" → near-instant download. Errors are reported via
  // the onError callback (never an unhandled rejection).
  async function _uploadShards(transferId, recipientId, file, fileKey, shards, startTime) {
    let sent = 0;
    try {
      await _pool(shards, CONCURRENCY, async (shard, idx) => {
        const plain = await file.slice(shard.start, shard.end).arrayBuffer();
        const iv    = crypto.getRandomValues(new Uint8Array(12));
        const enc   = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv }, fileKey, plain
        );
        // Wire format: [12B IV][ciphertext + 16B tag]
        const pkt = new Uint8Array(12 + enc.byteLength);
        pkt.set(iv, 0);
        pkt.set(new Uint8Array(enc), 12);

        const resp = await fetch(`/transfer/${transferId}/shard/${idx}`, {
          method: "POST",
          headers: { "Content-Type": "application/octet-stream" },
          body: pkt.buffer,
          credentials: "same-origin",
        });
        if (!resp.ok) throw new Error(`Shard ${idx} upload failed (${resp.status})`);

        sent += (shard.end - shard.start);
        const cb = _onProgress.get(transferId);
        if (cb) cb(sent, file.size);
      });
    } catch (err) {
      console.error("[FastTransfer] upload error", err);
      const cb = _onError.get(transferId);
      if (cb) cb(err);
      _socketSend("transfer_error", { transfer_id: transferId, recipient_id: recipientId });
      return;
    }

    const elapsed = (Date.now() - startTime) / 1000;
    console.log(`[FastTransfer] Uploaded ${file.name}: ` +
      `${(file.size/1048576).toFixed(1)} MB in ${elapsed.toFixed(1)}s = ` +
      `${(file.size/elapsed/1048576).toFixed(1)} MB/s`);

    const cb = _onComplete.get(transferId);
    if (cb) cb(file.name, file.size, elapsed);
  }

  function _computeShards(size) {
    const n = Math.max(1, Math.min(MAX_SHARDS, Math.ceil(size / SHARD_MAX)));
    const shardSize = Math.ceil(size / n);
    const shards = [];
    for (let i = 0; i < n; i++) {
      const start = i * shardSize;
      if (start >= size && i > 0) break;        // last shard already covered
      shards.push({ start, end: Math.min(start + shardSize, size) });
    }
    return shards;
  }

  // ════════════════════════════════════════════════════════════════
  // RECEIVER
  // ════════════════════════════════════════════════════════════════

  async function handleOffer(payload, privateKey) {
    const {
      transfer_id, sender_id, n_shards,
      sealed_key, key_ephem_pub, key_iv, meta_iv, meta_enc,
    } = payload;

    const fileKeyRaw = await _unsealKey(
      _unb64(sealed_key), key_ephem_pub, _unb64(key_iv), privateKey
    );
    const fileKey = await crypto.subtle.importKey(
      "raw", fileKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]
    );

    const metaBytes = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: _unb64(meta_iv) }, fileKey, _unb64(meta_enc)
    );
    const meta = JSON.parse(new TextDecoder().decode(metaBytes));

    _pending.set(transfer_id, { fileKey, sender_id, n_shards: n_shards || 1, meta });
    if (_onIncoming) _onIncoming(transfer_id, meta);
  }

  async function accept(transferId) {
    const p = _pending.get(transferId);
    if (!p) return;
    _pending.delete(transferId);

    const { fileKey, sender_id, n_shards, meta } = p;
    const startTime = Date.now();

    // Let the sender's UI know we accepted
    _socketSend("transfer_accept", { transfer_id: transferId, recipient_id: sender_id });

    let received = 0;
    try {
      const idxs = Array.from({ length: n_shards }, (_, i) => i);
      const parts = await _pool(idxs, CONCURRENCY, async (idx) => {
        const buf = await _getShard(transferId, idx);
        const view = new Uint8Array(buf);
        const iv   = view.slice(0, 12);
        const enc  = view.slice(12);
        const dec  = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, fileKey, enc);
        received += dec.byteLength;
        const cb = _onProgress.get(transferId);
        if (cb) cb(received, meta.size);
        return dec;   // index preserved by _pool
      });

      // Build the file from shard buffers in order. The Blob constructor
      // lets the browser back large data on disk — no 512 MB contiguous
      // allocation needed.
      const blob = new Blob(parts.map(b => new Uint8Array(b)), { type: meta.type });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = meta.name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 30000);

      _socketSend("transfer_complete", { transfer_id: transferId, recipient_id: sender_id });

      const elapsed = (Date.now() - startTime) / 1000;
      console.log(`[FastTransfer] Received ${meta.name}: ` +
        `${(meta.size/elapsed/1048576).toFixed(1)} MB/s`);
      const cb = _onComplete.get(transferId);
      if (cb) cb(meta.name, meta.size, elapsed);
    } catch (err) {
      const cb = _onError.get(transferId);
      if (cb) cb(err);
      _socketSend("transfer_error", { transfer_id: transferId, recipient_id: sender_id });
    }
  }

  // GET one shard, retrying while it is still uploading (HTTP 425).
  async function _getShard(transferId, idx) {
    for (let attempt = 0; attempt < GET_RETRY_MAX; attempt++) {
      const resp = await fetch(`/transfer/${transferId}/shard/${idx}`, {
        method: "GET", credentials: "same-origin",
      });
      if (resp.status === 425) {            // not uploaded yet — wait & retry
        await new Promise(r => setTimeout(r, GET_RETRY_MS));
        continue;
      }
      if (!resp.ok) throw new Error(`Shard ${idx} download failed (${resp.status})`);
      return await resp.arrayBuffer();
    }
    throw new Error(`Shard ${idx} timed out waiting for sender`);
  }

  function decline(transferId) {
    const p = _pending.get(transferId);
    if (!p) return;
    _pending.delete(transferId);
    _socketSend("transfer_decline", { transfer_id: transferId, recipient_id: p.sender_id });
  }

  // ════════════════════════════════════════════════════════════════
  // CRYPTO HELPERS (identical to the proven p2p_transfer.js)
  // ════════════════════════════════════════════════════════════════

  async function _sealKey(keyRaw, pubB64) {
    const pub = await crypto.subtle.importKey(
      "spki", _unb64(pubB64), { name: "ECDH", namedCurve: "P-256" }, false, []
    );
    const eph = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
    );
    const shared = await crypto.subtle.deriveKey(
      { name: "ECDH", public: pub }, eph.privateKey,
      { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    );
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, shared, keyRaw);
    const ephSpki = await crypto.subtle.exportKey("spki", eph.publicKey);
    return { encryptedKey: _b64(enc), ephemeralPub: _b64(ephSpki), iv: _b64(iv) };
  }

  async function _unsealKey(encBuf, ephPubB64, ivBuf, privKey) {
    const eph = await crypto.subtle.importKey(
      "spki", _unb64(ephPubB64), { name: "ECDH", namedCurve: "P-256" }, false, []
    );
    const shared = await crypto.subtle.deriveKey(
      { name: "ECDH", public: eph }, privKey,
      { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBuf }, shared, encBuf);
  }

  function _b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function _unb64(s) {
    const bin = atob(s); const b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    return b.buffer;
  }

  return {
    setSocketSend, send, handleOffer, onIncoming,
    accept, decline, onProgress, onComplete, onError,
  };
})();
