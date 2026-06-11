// p2p_transfer.js (v3)
// ─────────────────────────────────────────────────────────────────────
// WebRTC P2P file transfer
// Rebuilt per RFC 8831 (WebRTC Data Channels) and RFC 8260 (interleaving)
//
// Root cause of the 256 KB freeze in v2:
//   RFC 8831 §6.6 SHOULD limit message size to 16 KB without interleaving.
//   256 KB messages caused SCTP reassembly buffer stall on the receiver:
//   its SCTP layer waited for all 256 KB fragments before delivering ANY
//   data to JavaScript — the apparent freeze.
//
// Key changes from v2:
//   - Message size: 16 KB (RFC 8831 §6.6 SHOULD limit without interleaving)
//   - Multiple DataChannels: N streams share SCTP association, interleaved
//   - Nagle disabled: immediate send per RFC 8831 §6.6
//   - Stream priority: data=256 "normal", control=512 "high" per §6.4
//   - Credit system: retained for JS-layer flow control
//
// Public API (unchanged from v2):
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
// ─────────────────────────────────────────────────────────────────────

const P2PTransfer = (() => {

  // ── RFC 8831 §6.6: message size SHOULD be ≤ 16 KB without interleaving
  // We use 16 KB exactly. The browser's SCTP implementation handles
  // fragmentation at the IP layer per RFC 8831 §5 (PMTU discovery).
  // ─────────────────────────────────────────────────────────────────
  const MSG_SIZE       = 16 * 1024;    // 16 KB — RFC 8831 §6.6 limit
  const N_STREAMS      = 4;            // parallel SCTP streams (interleaving)
  const INITIAL_CREDITS = 16;          // larger pool — smaller messages need more
  const CREDIT_GRANT   = 8;            // grant credits in batches
  const BUFFER_HIGH    = 4 * 1024 * 1024;   // 4 MB buffer pause threshold
  const BUFFER_LOW     = 512 * 1024;         // 512 KB resume threshold

  // RFC 8831 §6.4 priority values
  // 128=below normal, 256=normal, 512=high, 1024=extra high
  const PRIORITY_DATA  = 256;   // "normal" for file data streams
  const PRIORITY_CTRL  = 512;   // "high" for control/ACK stream

  const CTRL_LABEL  = "intracomms-ctrl-v3";
  const DATA_PREFIX = "intracomms-data-v3-";   // + stream index

  let _socketSend   = null;
  const _transfers  = new Map();
  const _pending    = new Map();
  const _onProgress = new Map();
  const _onComplete = new Map();
  let   _onIncoming = null;

  function setSocketSend(fn)  { _socketSend  = fn; }
  function onProgress(id, fn) { _onProgress.set(id, fn); }
  function onComplete(id, fn) { _onComplete.set(id, fn); }
  function onIncoming(fn)     { _onIncoming  = fn; }

  // ════════════════════════════════════════════════════════════════
  // SENDER
  // ════════════════════════════════════════════════════════════════

  async function sendFile(file, recipientId, recipientPubKeyB64) {
    const transferId = crypto.randomUUID();
    const startTime  = Date.now();

    // Generate per-transfer AES-256-GCM key
    const fileKey    = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const fileKeyRaw = await crypto.subtle.exportKey("raw", fileKey);
    const sealed     = await _sealKey(fileKeyRaw, recipientPubKeyB64);

    // Create RTCPeerConnection
    const pc = _makePc();

    // ── Control DataChannel ──────────────────────────────────────
    // RFC 8831 §6.4: priority 512 = "high"
    // Created first so it gets a lower SCTP stream ID (client picks even)
    const ctrlDC = pc.createDataChannel(CTRL_LABEL, {
      ordered:   true,
      priority:  PRIORITY_CTRL,    // RFC 8831 §6.4
      protocol:  "intracomms-ctrl",
    });
    ctrlDC.binaryType = "arraybuffer";

    // ── N parallel data DataChannels ─────────────────────────────
    // RFC 8260: multiple streams on same SCTP association = interleaving
    // Each stream independently carries 1/N of the file
    // SCTP interleaves chunks across streams automatically
    const dataDCs = [];
    for (let i = 0; i < N_STREAMS; i++) {
      const dc = pc.createDataChannel(`${DATA_PREFIX}${i}`, {
        ordered:   true,
        priority:  PRIORITY_DATA,  // RFC 8831 §6.4
        protocol:  "intracomms-data",
      });
      dc.binaryType = "arraybuffer";
      dataDCs.push(dc);
    }

    // ── Sender state ─────────────────────────────────────────────
    const state = {
      role: "sender", pc, ctrlDC, dataDCs,
      file, fileKey, transferId, recipientId,
      credits: INITIAL_CREDITS,
      creditWaiters: [],
      bytesSent: 0, startTime,
    };
    _transfers.set(transferId, state);

    // ── Credit receiver (on control channel) ─────────────────────
    ctrlDC.onmessage = ({ data }) => {
      const msg = JSON.parse(data);
      if (msg.type === "credits") {
        state.credits += msg.n;
        // Reserve one credit per waiter we wake; the waiter does NOT
        // decrement again (decrementing in both places leaks a credit
        // per wait and eventually deadlocks the transfer).
        while (state.credits > 0 && state.creditWaiters.length > 0) {
          state.credits--;
          state.creditWaiters.shift()();
        }
      }
    };

    // ── Start streaming when all channels are open ────────────────
    let openCount = 0;
    const onOpen = () => {
      openCount++;
      if (openCount === N_STREAMS + 1) {  // all data + ctrl open
        _streamAllShards(state);
      }
    };
    ctrlDC.onopen  = onOpen;
    dataDCs.forEach(dc => { dc.onopen = onOpen; });

    // ── ICE ──────────────────────────────────────────────────────
    pc.onicecandidate = ({ candidate }) => {
      if (candidate) _socketSend("p2p_ice", {
        transfer_id: transferId, recipient_id: recipientId,
        candidate: candidate.toJSON(), direction: "sender",
      });
    };

    // ── Offer ────────────────────────────────────────────────────
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    _socketSend("p2p_offer", {
      transfer_id:   transferId,
      recipient_id:  recipientId,
      offer,
      n_streams:     N_STREAMS,
      sealed_key:    sealed.encryptedKey,
      key_ephem_pub: sealed.ephemeralPub,
      key_iv:        sealed.iv,
      file_name:     file.name,
      file_size:     file.size,
      file_type:     file.type,
    });

    return transferId;
  }

  // ── Stream all shards across N DataChannels in parallel ──────────
  // Each DataChannel gets a consecutive slice of the file.
  // Within each channel, messages are exactly MSG_SIZE (16 KB).
  // RFC 8260 interleaving: SCTP interleaves 16 KB chunks from all
  // streams so no single stream monopolises the SCTP association.

  async function _streamAllShards(state) {
    const { file, dataDCs } = state;
    const shardSize = Math.ceil(file.size / N_STREAMS);

    // Launch all N stream workers in parallel
    await Promise.all(
      dataDCs.map((dc, idx) => {
        const start = idx * shardSize;
        const end   = Math.min(start + shardSize, file.size);
        return _streamShard(state, dc, idx, start, end);
      })
    );

    // All shards sent — signal done on control channel
    state.ctrlDC.send(JSON.stringify({
      type: "done",
      total: state.bytesSent,
    }));

    const elapsed = (Date.now() - state.startTime) / 1000;
    console.log(
      `[P2P] Sent ${state.file.name}: ` +
      `${(state.file.size/1024/1024).toFixed(1)} MB in ` +
      `${elapsed.toFixed(1)}s = ` +
      `${(state.file.size/elapsed/1024/1024).toFixed(1)} MB/s`
    );
  }

  async function _streamShard(state, dc, shardIdx, start, end) {
    const slice  = state.file.slice(start, end);
    const reader = slice.stream().getReader();

    // Per-channel buffer backpressure (RFC 8831 compliance)
    dc.bufferedAmountLowThreshold = BUFFER_LOW;
    let _bufResolve = null;
    dc.onbufferedamountlow = () => {
      if (_bufResolve) { const r = _bufResolve; _bufResolve = null; r(); }
    };

    let seq = 0;

    // Accumulate raw bytes and send in exactly MSG_SIZE pieces
    // This is critical: RFC 8831 §6.6 says SCTP receiver must handle
    // exactly one application message per SCTP user message.
    // We stay at 16 KB to avoid SCTP reassembly stalls.
    let carry = new Uint8Array(0);   // leftover bytes < MSG_SIZE

    const sendMsg = async (raw) => {
      // Encrypt this 16 KB message
      // Wire format: [2B shardIdx uint16][4B seq uint32][12B IV][ciphertext+tag]
      const iv    = crypto.getRandomValues(new Uint8Array(12));
      const enc   = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv }, state.fileKey, raw
      );
      const hdr   = new Uint8Array(18);
      new DataView(hdr.buffer).setUint16(0, shardIdx, true);
      new DataView(hdr.buffer).setUint32(2, seq++,   true);
      hdr.set(iv, 6);

      const pkt = new Uint8Array(18 + enc.byteLength);
      pkt.set(hdr, 0);
      pkt.set(new Uint8Array(enc), 18);

      // Credit gate: wait for receiver to ACK before sending more.
      // If we waited, the credit-grant handler already consumed our
      // credit when it woke us; only decrement on the fast path.
      if (state.credits <= 0) {
        await new Promise(r => state.creditWaiters.push(r));
      } else {
        state.credits--;
      }

      // Buffer gate: pause if SCTP send buffer filling up
      if (dc.bufferedAmount > BUFFER_HIGH) {
        await new Promise(r => { _bufResolve = r; });
      }

      // RFC 8831 §6.6: disable Nagle by sending immediately
      // (dc.send doesn't batch when called per-message like this)
      dc.send(pkt.buffer);

      state.bytesSent += raw.byteLength;
      const cb = _onProgress.get(state.transferId);
      if (cb) cb(state.bytesSent, state.file.size);
    };

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      // Merge with carry and process in MSG_SIZE chunks
      const combined = new Uint8Array(carry.byteLength + value.byteLength);
      combined.set(carry, 0);
      combined.set(value, carry.byteLength);

      let offset = 0;
      while (offset + MSG_SIZE <= combined.byteLength) {
        await sendMsg(combined.slice(offset, offset + MSG_SIZE));
        offset += MSG_SIZE;
      }
      carry = combined.slice(offset);   // save remainder < MSG_SIZE
    }

    // Send final partial message if any
    if (carry.byteLength > 0) {
      await sendMsg(carry);
    }

    // Signal end of this shard on control channel
    state.ctrlDC.send(JSON.stringify({
      type: "shard_done", shard: shardIdx,
    }));
  }

  // ════════════════════════════════════════════════════════════════
  // RECEIVER
  // ════════════════════════════════════════════════════════════════

  async function handleOffer(payload, privateKey) {
    const {
      transfer_id, sender_id, offer,
      n_streams, sealed_key, key_ephem_pub, key_iv,
      file_name, file_size, file_type,
    } = payload;

    // Unseal file key before user accepts — no delay when they click accept
    const fileKeyRaw = await _unsealKey(
      _unb64(sealed_key), key_ephem_pub, _unb64(key_iv), privateKey
    );
    const fileKey = await crypto.subtle.importKey(
      "raw", fileKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]
    );

    _pending.set(transfer_id, {
      offer, fileKey, sender_id, n_streams: n_streams || N_STREAMS,
      meta: { name: file_name, size: file_size, type: file_type },
    });

    if (_onIncoming) _onIncoming(transfer_id, {
      name: file_name, size: file_size, type: file_type,
    });
  }

  async function accept(transferId) {
    const pending = _pending.get(transferId);
    if (!pending) return;
    _pending.delete(transferId);

    const { offer, fileKey, sender_id, n_streams, meta } = pending;
    const startTime = Date.now();

    const pc = _makePc();

    // ── Receiver state ────────────────────────────────────────────
    // chunks: Map<shardIdx, Map<seq, ArrayBuffer>>
    // shardsComplete: Set<shardIdx>
    const state = {
      role: "receiver", pc, fileKey, meta,
      transferId, startTime,
      chunks:         new Map(),  // shardIdx → Map<seq, ArrayBuffer>
      shardsComplete: new Set(),
      totalReceived:  0,
      nShards:        n_streams,
      ctrlDC:         null,
      batchCount:     0,          // messages received since last credit grant
      assembled:      false,      // guard: assemble exactly once
    };
    for (let i = 0; i < n_streams; i++) {
      state.chunks.set(i, new Map());
    }
    _transfers.set(transferId, state);

    // ── Handle incoming DataChannels ──────────────────────────────
    pc.ondatachannel = ({ channel }) => {
      channel.binaryType = "arraybuffer";

      if (channel.label === CTRL_LABEL) {
        state.ctrlDC = channel;
        channel.onopen = () => {
          // Grant initial credits immediately
          _grant(state, INITIAL_CREDITS);
        };
        channel.onmessage = ({ data }) => _handleCtrl(state, data);

      } else if (channel.label.startsWith(DATA_PREFIX)) {
        const shardIdx = parseInt(channel.label.replace(DATA_PREFIX, ""), 10);
        channel.onmessage = ({ data }) => _handleData(state, shardIdx, data);
        channel.onerror   = (e) => console.error(`[P2P] Shard ${shardIdx} error`, e);
      }
    };

    // ── ICE ──────────────────────────────────────────────────────
    pc.onicecandidate = ({ candidate }) => {
      if (candidate) _socketSend("p2p_ice", {
        transfer_id: transferId, recipient_id: sender_id,
        candidate: candidate.toJSON(), direction: "receiver",
      });
    };

    // ── Answer ───────────────────────────────────────────────────
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    _socketSend("p2p_answer", {
      transfer_id: transferId, recipient_id: sender_id, answer,
    });
  }

  function decline(transferId) {
    const p = _pending.get(transferId);
    if (!p) return;
    _pending.delete(transferId);
    _socketSend("p2p_decline", { transfer_id: transferId, recipient_id: p.sender_id });
  }

  // ── Handle incoming data message ─────────────────────────────────
  // Wire format: [2B shardIdx][4B seq][12B IV][ciphertext+tag]
  function _handleData(state, shardIdx, data) {
    const buf      = new Uint8Array(data);
    const view     = new DataView(data);
    const seq      = view.getUint32(2, true);
    const iv       = buf.slice(6, 18);
    const enc      = buf.slice(18);

    // Decrypt asynchronously — don't block onmessage callback
    // This is critical: blocking here starves the SCTP receive buffer
    crypto.subtle.decrypt({ name: "AES-GCM", iv }, state.fileKey, enc)
      .then(plain => {
        state.chunks.get(shardIdx).set(seq, plain);
        state.totalReceived += plain.byteLength;

        const cb = _onProgress.get(state.transferId);
        if (cb) cb(state.totalReceived, state.meta.size);

        // Grant credits after every CREDIT_GRANT messages
        // This is receiver-driven: sender cannot exceed this pace
        state.batchCount++;
        if (state.batchCount >= CREDIT_GRANT) {
          _grant(state, CREDIT_GRANT);
          state.batchCount = 0;
        }
      })
      .catch(e => console.error(`[P2P] Decrypt error shard=${shardIdx} seq=${seq}`, e));
  }

  // ── Handle control message ────────────────────────────────────────
  async function _handleCtrl(state, data) {
    const msg = JSON.parse(data);

    if (msg.type === "shard_done") {
      state.shardsComplete.add(msg.shard);
    }

    if (msg.type === "done" || state.shardsComplete.size === state.nShards) {
      // Both the last shard_done and the final done message reach this
      // branch — assemble exactly once.
      if (state.assembled) return;
      state.assembled = true;
      // Wait for in-flight data messages and async decrypts to land
      await _waitDecrypts(state);
      await _assembleFile(state);
    }
  }

  async function _waitDecrypts(state) {
    // The ctrl channel is a separate SCTP stream, so "done" can arrive
    // before the last data messages. Poll until every plaintext byte
    // has landed (decrypt callbacks bump totalReceived).
    const maxWait = 10000;  // 10 second timeout
    const start   = Date.now();
    while (Date.now() - start < maxWait) {
      if (state.totalReceived >= state.meta.size) break;
      await new Promise(r => setTimeout(r, 20));
    }
    if (state.totalReceived < state.meta.size) {
      console.warn(
        `[P2P] Timed out waiting for data: ${state.totalReceived}/${state.meta.size} bytes`
      );
    }
  }

  async function _assembleFile(state) {
    // For each shard, sort by seq and concatenate
    // Then concatenate shards in order
    const parts = [];
    for (let shardIdx = 0; shardIdx < state.nShards; shardIdx++) {
      const shardMap  = state.chunks.get(shardIdx);
      const sortedSeqs = [...shardMap.keys()].sort((a, b) => a - b);
      for (const seq of sortedSeqs) {
        parts.push(new Uint8Array(shardMap.get(seq)));
      }
    }

    const totalBytes = parts.reduce((s, p) => s + p.byteLength, 0);
    const output     = new Uint8Array(totalBytes);
    let   pos        = 0;
    for (const part of parts) { output.set(part, pos); pos += part.byteLength; }

    const blob = new Blob([output], { type: state.meta.type });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = state.meta.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Revoke after a delay — revoking synchronously after click() can cancel
    // the download before the browser has read the blob data.
    setTimeout(() => URL.revokeObjectURL(url), 30000);

    const elapsed = (Date.now() - state.startTime) / 1000;
    const mbps    = (state.meta.size / elapsed / 1024 / 1024).toFixed(1);
    console.log(`[P2P] Received ${state.meta.name}: ${mbps} MB/s`);

    const cb = _onComplete.get(state.transferId);
    if (cb) cb(state.meta.name, state.meta.size, elapsed);

    state.pc.close();
    _transfers.delete(state.transferId);
  }

  // ── Grant credits to sender ───────────────────────────────────────
  function _grant(state, n) {
    if (!state.ctrlDC || state.ctrlDC.readyState !== "open") return;
    state.ctrlDC.send(JSON.stringify({ type: "credits", n }));
  }

  // ════════════════════════════════════════════════════════════════
  // SIGNALLING
  // ════════════════════════════════════════════════════════════════

  async function handleAnswer({ transfer_id, answer }) {
    const s = _transfers.get(transfer_id);
    if (s) await s.pc.setRemoteDescription(new RTCSessionDescription(answer));
  }

  async function handleIce({ transfer_id, candidate }) {
    const s = _transfers.get(transfer_id);
    if (!s) return;
    try { await s.pc.addIceCandidate(new RTCIceCandidate(candidate)); }
    catch (e) { console.warn("[P2P] ICE", e); }
  }

  // ════════════════════════════════════════════════════════════════
  // HELPERS
  // ════════════════════════════════════════════════════════════════

  function _makePc() {
    return new RTCPeerConnection({
      iceServers: [],
      iceCandidatePoolSize: 1,
      // bundlePolicy: "max-bundle" ensures all DataChannels share
      // one DTLS connection → one SCTP association → RFC 8260 interleaving
      bundlePolicy: "max-bundle",
    });
  }

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
    setSocketSend, onProgress, onComplete, onIncoming,
    sendFile, handleOffer, handleAnswer, handleIce,
    accept, decline,
  };
})();
