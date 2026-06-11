// voice_chat.js
// Real-time voice calls over WebRTC MediaStream
// Server: signalling relay only — never receives audio bytes
// Audio:  direct browser-to-browser, Opus codec, DTLS/SRTP encrypted

const VoiceChat = (() => {
    // Call state machine: idle → calling → ringing → in_call → ended → idle
    let _state        = "idle";
    let _pc           = null;
    let _localStream  = null;
    let _callId       = null;
    let _peerId       = null;
    let _peerName     = null;
    let _isCaller          = false;
    let _pendingOffer      = null;
    let _iceCandidateQueue = [];  // candidates received before PC was ready
    let _socketSend      = null;  // fn(event, data) — set via setSocketSend()
    let _onStateChangeCb = null;
    let _onDeclineCb     = null;

    function setSocketSend(fn) { _socketSend = fn; }
    function onStateChange(fn) { _onStateChangeCb = fn; }
    function onDecline(fn)     { _onDeclineCb = fn; }

    function _send(event, data) {
        if (_socketSend) _socketSend(event, data);
    }

    function _setState(s) {
        _state = s;
        if (_onStateChangeCb) _onStateChangeCb(s, _peerId, _peerName);
    }

    // ── CALLER: initiate call ────────────────────────────────────────────
    async function startCall(recipientId, recipientName) {
        if (_state !== "idle") {
            console.warn("[Voice] Already in a call");
            return;
        }
        _callId   = crypto.randomUUID();
        _peerId   = recipientId;
        _peerName = recipientName;
        _isCaller = true;
        _setState("calling");

        try {
            _localStream = await navigator.mediaDevices.getUserMedia({
                audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
                video: false,
            });
        } catch (err) {
            console.error("[Voice] Microphone access denied:", err);
            _setState("idle");
            _cleanup();
            throw new Error("Microphone access denied — check browser permissions.");
        }

        _pc = _createPeerConnection();
        _localStream.getTracks().forEach(t => _pc.addTrack(t, _localStream));

        const offer = await _pc.createOffer();
        await _pc.setLocalDescription(offer);

        _send("call_invite", {
            call_id:      _callId,
            recipient_id: recipientId,
            offer:        offer,
        });
    }

    // ── CALLEE: incoming call invite ─────────────────────────────────────
    async function handleInvite(payload) {
        if (_state !== "idle") {
            _send("call_decline", { call_id: payload.call_id, recipient_id: payload.caller_id, reason: "busy" });
            return;
        }
        _callId       = payload.call_id;
        _peerId       = payload.caller_id;
        _peerName     = payload.caller_name;
        _isCaller     = false;
        _pendingOffer = payload.offer;
        _setState("ringing");
    }

    // ── CALLEE: accept ────────────────────────────────────────────────────
    async function acceptCall() {
        if (_state !== "ringing" || !_pendingOffer) return;
        _setState("in_call");

        try {
            _localStream = await navigator.mediaDevices.getUserMedia({
                audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
                video: false,
            });
        } catch (err) {
            console.error("[Voice] Microphone access denied:", err);
            _setState("idle");
            _cleanup();
            return;
        }

        _pc = _createPeerConnection();
        _localStream.getTracks().forEach(t => _pc.addTrack(t, _localStream));

        await _pc.setRemoteDescription(new RTCSessionDescription(_pendingOffer));
        await _drainIceQueue();  // apply any candidates that arrived while ringing
        const answer = await _pc.createAnswer();
        await _pc.setLocalDescription(answer);

        _send("call_accept", { call_id: _callId, recipient_id: _peerId, answer });
        _pendingOffer = null;
    }

    // ── CALLEE: decline ────────────────────────────────────────────────────
    function declineCall() {
        if (_state !== "ringing") return;
        _send("call_decline", { call_id: _callId, recipient_id: _peerId, reason: "declined" });
        _setState("idle");
        _cleanup();
    }

    // ── CALLER: receive answer ─────────────────────────────────────────────
    async function handleAccept(payload) {
        if (!_pc || _state !== "calling") return;
        await _pc.setRemoteDescription(new RTCSessionDescription(payload.answer));
        await _drainIceQueue();  // apply any callee candidates that arrived before answer was processed
        _setState("in_call");
    }

    // ── Handle decline from remote ─────────────────────────────────────────
    function handleDecline(payload) {
        const reason = payload.reason || "declined";
        _setState("idle");
        _cleanup();
        if (_onDeclineCb) _onDeclineCb(reason);
    }

    // ── Handle ICE candidate from remote ──────────────────────────────────
    async function handleIce(payload) {
        if (!_pc) {
            // PC not created yet (callee still on ringing screen, or caller waiting for answer).
            // Queue the candidate — it will be applied after the PC and remote description are set.
            _iceCandidateQueue.push(payload.candidate);
            return;
        }
        try {
            await _pc.addIceCandidate(new RTCIceCandidate(payload.candidate));
        } catch (e) {
            console.warn("[Voice] ICE error:", e);
        }
    }

    async function _drainIceQueue() {
        const queued = _iceCandidateQueue.splice(0);
        for (const c of queued) {
            try { await _pc.addIceCandidate(new RTCIceCandidate(c)); }
            catch (e) { console.warn("[Voice] queued ICE error:", e); }
        }
    }

    // ── End call (either side) ─────────────────────────────────────────────
    function endCall() {
        if (_state === "idle") return;
        _send("call_end", { call_id: _callId, recipient_id: _peerId });
        _setState("ended");
        _cleanup();
        setTimeout(() => _setState("idle"), 1500);
    }

    // ── Handle remote end ──────────────────────────────────────────────────
    function handleEnd() {
        if (_state === "idle") return;
        _setState("ended");
        _cleanup();
        setTimeout(() => _setState("idle"), 1500);
    }

    // ── Mute / unmute ──────────────────────────────────────────────────────
    function setMuted(muted) {
        if (!_localStream) return;
        _localStream.getAudioTracks().forEach(t => { t.enabled = !muted; });
    }

    function isMuted() {
        if (!_localStream) return true;
        return !_localStream.getAudioTracks().some(t => t.enabled);
    }

    // ── RTCPeerConnection factory ──────────────────────────────────────────
    function _createPeerConnection() {
        const ICE_CONFIG = {
            iceServers: [
                { urls: "stun:stun.l.google.com:19302" },
                { urls: "stun:stun1.l.google.com:19302" },
            ]
        };
        const pc = new RTCPeerConnection(ICE_CONFIG);

        pc.onicecandidate = ({ candidate }) => {
            if (candidate) {
                _send("call_ice", { call_id: _callId, recipient_id: _peerId, candidate: candidate.toJSON() });
            }
        };

        pc.ontrack = ({ streams }) => {
            _playRemoteAudio(streams[0]);
        };

        pc.onconnectionstatechange = () => {
            if (pc.connectionState === "failed" || pc.connectionState === "disconnected") {
                endCall();
            }
        };

        return pc;
    }

    // ── Play remote audio ──────────────────────────────────────────────────
    function _playRemoteAudio(stream) {
        let el = document.getElementById("_voiceRemoteAudio");
        if (!el) {
            el = document.createElement("audio");
            el.id = "_voiceRemoteAudio";
            el.autoplay = true;
            el.style.display = "none";
            document.body.appendChild(el);
        }
        el.srcObject = stream;
    }

    // ── Cleanup ────────────────────────────────────────────────────────────
    function _cleanup() {
        if (_localStream) { _localStream.getTracks().forEach(t => t.stop()); _localStream = null; }
        if (_pc) { _pc.close(); _pc = null; }
        const el = document.getElementById("_voiceRemoteAudio");
        if (el) el.srcObject = null;
        _callId = null; _peerId = null; _peerName = null;
        _pendingOffer = null; _isCaller = false;
        _iceCandidateQueue = [];
    }

    return {
        setSocketSend, onStateChange, onDecline,
        startCall,
        handleInvite, acceptCall, declineCall,
        handleAccept, handleDecline, handleIce, handleEnd,
        endCall, setMuted, isMuted,
        get state() { return _state; },
    };
})();
