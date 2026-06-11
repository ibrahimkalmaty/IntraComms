// p2p_transfer.js
// WebRTC P2P file transfer with credit-based flow control.
// File bytes never touch the server; server only relays offer/answer/ICE.
//
// Public API:
//   P2PTransfer.setSocketSend(fn)                   fn(event, data)
//   P2PTransfer.sendFile(file, recipientId, recipientPubKeyB64) → Promise<transferId>
//   P2PTransfer.handleOffer(payload, privateKey)
//   P2PTransfer.handleAnswer(payload)
//   P2PTransfer.handleIce(payload)
//   P2PTransfer.onProgress(transferId, fn)           fn(bytesSent, total)
//   P2PTransfer.onComplete(transferId, fn)           fn(filename, size, elapsed)
//   P2PTransfer.onIncoming(fn)                       fn(transferId, {name,size,type})
//   P2PTransfer.accept(transferId)
//   P2PTransfer.decline(transferId)

const P2PTransfer = (() => {

  // ── Tuning ──────────────────────────────────────────────────────────────
  const CHUNK_SIZE      = 256 * 1024;        // 256 KB per chunk
  const INITIAL_CREDITS = 8;                 // sender starts with 8 send slots
  const CREDIT_GRANT    = 4;                 // receiver grants 4 credits per batch
  const BUFFER_HIGH     = 8  * 1024 * 1024; // pause sending at 8 MB buffered
  const BUFFER_LOW      = 2  * 1024 * 1024; // resume at 2 MB
  const DATA_CHANNEL    = "intracomms-data-v2";
  const CTRL_CHANNEL    = "intracomms-ctrl-v2";

  // ── State ────────────────────────────────────────────────────────────────
  let _socketSend  = null;
  const _transfers = new Map();  // transferId → state object
  const _pending   = new Map();  // transferId → {offer, fileKey, sender_id, meta}

  // Callbacks
  const _onProgress = new Map(); // transferId → fn(sent, total)
  const _onComplete = new Map(); // transferId → fn(filename, size, elapsed)
  let   _onIncoming = null;      // fn(transferId, {name, size, type})

  function setSocketSend(fn)  { _socketSend = fn; }
  function onProgress(id, fn) { _onProgress.set(id, fn); }
  function onComplete(id, fn) { _onComplete.set(id, fn); }
  function onIncoming(fn)     { _onIncoming = fn; }

  // ── SENDER ───────────────────────────────────────────────────────────────

  async function sendFile(file, recipientId, recipientPubKeyB64) {
    const transferId = crypto.randomUUID();
    const startTime  = Date.now();

    // Generate per-transfer AES-256-GCM key
    const fileKey    = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const fileKeyRaw = await crypto.subtle.exportKey("raw", fileKey);

    // Seal key for recipient using ECIES (ECDH P-256 + AES-GCM)
    const sealed = await _sealKey(fileKeyRaw, recipientPubKeyB64);

    const pc = _makePeerConnection();

    // Ordered reliable data channel for file chunks (sender → receiver)
    const dataDC = pc.createDataChannel(DATA_CHANNEL, {
      ordered: true, protocol: "intracomms-p2p-v2",
    });
    dataDC.binaryType = "arraybuffer";

    // Ordered reliable control channel for ACK/credits (receiver → sender)
    const ctrlDC = pc.createDataChannel(CTRL_CHANNEL, {
      ordered: true, protocol: "intracomms-p2p-ctrl-v2",
    });

    const state = {
      role: "sender", pc, dataDC, ctrlDC,
      file, fileKey, transferId, recipientId,
      credits: INITIAL_CREDITS,
      creditWaiters: [],
      bytesSent: 0, startTime,
    };
    _transfers.set(transferId, state);

    // Credit-based flow: receiver grants credits as it processes chunks
    ctrlDC.onmessage = ({ data }) => {
      const msg = JSON.parse(data);
      if (msg.type === "credits") {
        state.credits += msg.n;
        // Reserve one credit per waiter we wake; the waiter does NOT decrement again
        while (state.credits > 0 && state.creditWaiters.length > 0) {
          state.credits--;
          state.creditWaiters.shift()();
        }
      }
    };

    // Buffer backpressure: pause when DataChannel buffer fills
    dataDC.bufferedAmountLowThreshold = BUFFER_LOW;
    let _bufferResolve = null;
    dataDC.onbufferedamountlow = () => {
      if (_bufferResolve) { const r = _bufferResolve; _bufferResolve = null; r(); }
    };

    dataDC.onopen  = () => _streamSender(state, (r) => { _bufferResolve = r; });
    dataDC.onerror = (e) => console.error("[P2P] Data channel error", e);

    pc.onicecandidate = ({ candidate }) => {
      if (candidate) {
        _socketSend("p2p_ice", {
          transfer_id: transferId, recipient_id: recipientId,
          candidate: candidate.toJSON(), direction: "sender",
        });
      }
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    _socketSend("p2p_offer", {
      transfer_id:   transferId,
      recipient_id:  recipientId,
      offer,
      sealed_key:    sealed.encryptedKey,
      key_ephem_pub: sealed.ephemeralPub,
      key_iv:        sealed.iv,
      file_name:     file.name,
      file_size:     file.size,
      file_type:     file.type,
    });

    return transferId;
  }

  // Core send loop — event-driven, pipelined encryption
  async function _streamSender(state, setBufferResolve) {
    const { file, fileKey, dataDC } = state;
    const reader = file.stream().getReader();
    let chunkIdx = 0;

    const chunkStream = [];
    let streamDone = false;

    // Read file into chunkStream in the background
    (async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) { streamDone = true; return; }
        for (let i = 0; i < value.byteLength; i += CHUNK_SIZE)
          chunkStream.push(value.slice(i, i + CHUNK_SIZE));
      }
    })();

    const encryptChunk = async (rawBuf) => {
      const iv  = crypto.getRandomValues(new Uint8Array(12));
      const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, fileKey, rawBuf);
      // Wire format: [4B seq uint32][12B IV][ciphertext+tag]
      const seq = new Uint8Array(new Uint32Array([chunkIdx++]).buffer);
      const pkt = new Uint8Array(4 + 12 + enc.byteLength);
      pkt.set(seq, 0); pkt.set(iv, 4); pkt.set(new Uint8Array(enc), 16);
      return pkt;
    };

    let nextEncrypted = null;

    while (true) {
      while (chunkStream.length === 0 && !streamDone)
        await new Promise(r => setTimeout(r, 2));
      if (chunkStream.length === 0 && streamDone) break;

      const rawChunk = chunkStream.shift();

      // Pipeline: start encrypting the next chunk while sending this one
      if (nextEncrypted === null) nextEncrypted = encryptChunk(rawChunk);
      const encrypted = await nextEncrypted;
      nextEncrypted = chunkStream.length > 0 ? encryptChunk(chunkStream[0]) : null;

      // Block if receiver hasn't granted more credits.
      // If we waited, the wakeup handler already consumed the credit (state.credits--).
      // If we didn't wait, consume it here. Never decrement twice.
      if (state.credits <= 0) {
        await new Promise(resolve => state.creditWaiters.push(resolve));
      } else {
        state.credits--;
      }

      // Block if DataChannel buffer is backed up
      if (dataDC.bufferedAmount > BUFFER_HIGH)
        await new Promise(resolve => setBufferResolve(resolve));

      dataDC.send(encrypted.buffer);
      state.bytesSent += rawChunk.byteLength;

      const cb = _onProgress.get(state.transferId);
      if (cb) cb(state.bytesSent, file.size);
    }

    dataDC.send(JSON.stringify({ type: "done", total: state.bytesSent }));

    const elapsed = (Date.now() - state.startTime) / 1000;
    console.log(`[P2P] Sent ${file.name}: ${(file.size/1048576).toFixed(1)} MB `
      + `in ${elapsed.toFixed(1)}s = ${(file.size/elapsed/1048576).toFixed(1)} MB/s`);
  }

  // ── RECEIVER ─────────────────────────────────────────────────────────────

  async function handleOffer(payload, privateKey) {
    const { transfer_id, sender_id, offer,
            sealed_key, key_ephem_pub, key_iv,
            file_name, file_size, file_type } = payload;

    // Unseal file key before user accepts so accept() starts instantly
    const fileKeyRaw = await _unsealKey(
      _unb64(sealed_key), key_ephem_pub, _unb64(key_iv), privateKey
    );
    const fileKey = await crypto.subtle.importKey(
      "raw", fileKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]
    );

    _pending.set(transfer_id, {
      offer, fileKey, sender_id,
      meta: { name: file_name, size: file_size, type: file_type },
    });

    if (_onIncoming) _onIncoming(transfer_id, { name: file_name, size: file_size, type: file_type });
  }

  async function accept(transferId) {
    const pending = _pending.get(transferId);
    if (!pending) return;
    _pending.delete(transferId);

    const { offer, fileKey, sender_id, meta } = pending;
    const startTime = Date.now();
    const pc = _makePeerConnection();

    const state = {
      role: "receiver", pc, fileKey,
      transferId, meta, startTime,
      chunks: new Map(),
      nextSeq: 0, totalReceived: 0,
      dataDC: null, ctrlDC: null,
    };
    _transfers.set(transferId, state);

    pc.ondatachannel = ({ channel }) => {
      if (channel.label === DATA_CHANNEL) {
        channel.binaryType = "arraybuffer";
        state.dataDC = channel;
        _setupReceiverDataChannel(state, channel);
      } else if (channel.label === CTRL_CHANNEL) {
        state.ctrlDC = channel;
        channel.onopen = () => _grantCredits(state, INITIAL_CREDITS);
      }
    };

    pc.onicecandidate = ({ candidate }) => {
      if (candidate) {
        _socketSend("p2p_ice", {
          transfer_id: transferId, recipient_id: sender_id,
          candidate: candidate.toJSON(), direction: "receiver",
        });
      }
    };

    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    _socketSend("p2p_answer", { transfer_id: transferId, recipient_id: sender_id, answer });
  }

  function decline(transferId) {
    const pending = _pending.get(transferId);
    if (!pending) return;
    _pending.delete(transferId);
    _socketSend("p2p_decline", { transfer_id: transferId, recipient_id: pending.sender_id });
  }

  function _setupReceiverDataChannel(state, dc) {
    let batchReceived = 0;

    dc.onmessage = async ({ data }) => {
      if (typeof data === "string") {
        const msg = JSON.parse(data);
        if (msg.type === "done") { await _finaliseFile(state); return; }
      }

      // Wire format: [4B seq uint32][12B IV][ciphertext+tag]
      const buf = new Uint8Array(data);
      const seq = new DataView(data).getUint32(0, true);
      const iv  = buf.slice(4, 16);
      const enc = buf.slice(16);

      crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.fileKey, enc)
        .then(plain => {
          state.chunks.set(seq, plain);
          state.totalReceived += plain.byteLength;

          const cb = _onProgress.get(state.transferId);
          if (cb) cb(state.totalReceived, state.meta.size);

          // Count completed decrypts (not arrivals) so rapid batch arrival
          // doesn't reset the counter before all .then() callbacks run.
          batchReceived++;
          if (batchReceived >= CREDIT_GRANT) {
            _grantCredits(state, CREDIT_GRANT);
            batchReceived = 0;
          }
        })
        .catch(e => console.error("[P2P] Decrypt error seq", seq, e));
    };

    dc.onerror = (e) => console.error("[P2P] DataChannel error", e);
    dc.onclose = () => console.log("[P2P] DataChannel closed");
  }

  function _grantCredits(state, n) {
    if (!state.ctrlDC || state.ctrlDC.readyState !== "open") return;
    state.ctrlDC.send(JSON.stringify({ type: "credits", n }));
  }

  async function _finaliseFile(state) {
    // Wait for any in-flight async decryptions to land
    const expectedChunks = Math.ceil(state.meta.size / CHUNK_SIZE);
    let waited = 0;
    while (state.chunks.size < expectedChunks && waited < 100) {
      await new Promise(r => setTimeout(r, 20));
      waited++;
    }

    const sortedKeys = [...state.chunks.keys()].sort((a, b) => a - b);
    const parts      = sortedKeys.map(k => new Uint8Array(state.chunks.get(k)));
    const totalBytes = parts.reduce((s, p) => s + p.byteLength, 0);
    const output     = new Uint8Array(totalBytes);
    let pos = 0;
    for (const part of parts) { output.set(part, pos); pos += part.byteLength; }

    const blob = new Blob([output], { type: state.meta.type });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = state.meta.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Revoke after a delay — revoking synchronously after click() can cancel
    // the download before the browser has read the blob data.
    setTimeout(() => URL.revokeObjectURL(url), 30000);

    const elapsed = (Date.now() - state.startTime) / 1000;
    console.log(`[P2P] Received ${state.meta.name}: ${(state.meta.size/elapsed/1048576).toFixed(1)} MB/s`);

    const cb = _onComplete.get(state.transferId);
    if (cb) cb(state.meta.name, state.meta.size, elapsed);

    state.pc.close();
    _transfers.delete(state.transferId);
  }

  // ── SIGNALLING ────────────────────────────────────────────────────────────

  async function handleAnswer({ transfer_id, answer }) {
    const state = _transfers.get(transfer_id);
    if (!state) return;
    await state.pc.setRemoteDescription(new RTCSessionDescription(answer));
  }

  async function handleIce({ transfer_id, candidate }) {
    const state = _transfers.get(transfer_id);
    if (!state) return;
    try { await state.pc.addIceCandidate(new RTCIceCandidate(candidate)); }
    catch (e) { console.warn("[P2P] ICE error", e); }
  }

  // ── HELPERS ───────────────────────────────────────────────────────────────

  function _makePeerConnection() {
    return new RTCPeerConnection({ iceServers: [], iceCandidatePoolSize: 1 });
  }

  async function _sealKey(keyRaw, recipientPubB64) {
    const recipientPub = await crypto.subtle.importKey(
      "spki", _unb64(recipientPubB64),
      { name: "ECDH", namedCurve: "P-256" }, false, []
    );
    const eph = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
    );
    const shared = await crypto.subtle.deriveKey(
      { name: "ECDH", public: recipientPub }, eph.privateKey,
      { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    );
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, shared, keyRaw);
    const ephSpki = await crypto.subtle.exportKey("spki", eph.publicKey);
    return { encryptedKey: _b64(enc), ephemeralPub: _b64(ephSpki), iv: _b64(iv) };
  }

  async function _unsealKey(encBuf, ephPubB64, ivBuf, privKey) {
    const ephPub = await crypto.subtle.importKey(
      "spki", _unb64(ephPubB64),
      { name: "ECDH", namedCurve: "P-256" }, false, []
    );
    const shared = await crypto.subtle.deriveKey(
      { name: "ECDH", public: ephPub }, privKey,
      { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    return await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBuf }, shared, encBuf);
  }

  function _b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }
  function _unb64(s) {
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  return {
    setSocketSend, onProgress, onComplete, onIncoming,
    sendFile, handleOffer, handleAnswer, handleIce,
    accept, decline,
  };
})();
