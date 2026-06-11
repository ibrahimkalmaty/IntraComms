// voice_message.js
// ─────────────────────────────────────────────────────────────────
// Voice message recording and playback
//
// Recording:  MediaRecorder → chunks → Blob → File
// Upload:     FileE2EE.uploadEncryptedFile() — existing E2EE pipeline
// Playback:   FileE2EE.downloadAndDecrypt() → Blob URL → <audio>
//
// No new server routes. No WebRTC. No signalling.
// ─────────────────────────────────────────────────────────────────

// ── VoiceRecorder ─────────────────────────────────────────────────

const VoiceRecorder = (() => {
    let _mediaRecorder  = null;
    let _chunks         = [];
    let _stream         = null;
    let _startTime      = null;
    let _timerInterval  = null;
    let _analyser       = null;
    let _audioCtx       = null;

    let _onTick      = null;   // (elapsedSeconds) => {}
    let _onLevel     = null;   // (0..1 amplitude) => {}
    let _onComplete  = null;   // (File, durationSeconds) => {}
    let _onCancel    = null;   // () => {}

    function onTick(fn)     { _onTick     = fn; }
    function onLevel(fn)    { _onLevel    = fn; }
    function onComplete(fn) { _onComplete = fn; }
    function onCancel(fn)   { _onCancel   = fn; }

    async function start() {
        if (_mediaRecorder) return;

        _stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });

        const mimeType = [
            "audio/webm;codecs=opus",
            "audio/webm",
            "audio/ogg;codecs=opus",
            "audio/ogg",
        ].find(t => MediaRecorder.isTypeSupported(t)) || "";

        _mediaRecorder = new MediaRecorder(_stream, mimeType ? { mimeType } : {});
        _chunks = [];
        _startTime = Date.now();

        _mediaRecorder.ondataavailable = e => {
            if (e.data.size > 0) _chunks.push(e.data);
        };
        _mediaRecorder.onstop = _handleStop;

        _mediaRecorder.start(200);

        _timerInterval = setInterval(() => {
            const elapsed = (Date.now() - _startTime) / 1000;
            if (_onTick) _onTick(elapsed);
            if (elapsed >= 300) stop();   // auto-stop at 5 min
        }, 100);

        _audioCtx = new AudioContext();
        const source = _audioCtx.createMediaStreamSource(_stream);
        _analyser = _audioCtx.createAnalyser();
        _analyser.fftSize = 256;
        source.connect(_analyser);
        _animateLevel();
    }

    function stop() {
        if (!_mediaRecorder || _mediaRecorder.state === "inactive") return;
        _mediaRecorder.stop();
        clearInterval(_timerInterval);
    }

    function cancel() {
        if (_mediaRecorder && _mediaRecorder.state !== "inactive") {
            _mediaRecorder.stop();
        }
        _chunks = [];
        clearInterval(_timerInterval);
        _cleanup();
        if (_onCancel) _onCancel();
    }

    function _handleStop() {
        const duration = _startTime ? (Date.now() - _startTime) / 1000 : 0;
        const mimeType = (_mediaRecorder && _mediaRecorder.mimeType) || "audio/webm";
        _cleanup();

        if (_chunks.length === 0) {
            if (_onCancel) _onCancel();
            return;
        }
        const blob     = new Blob(_chunks, { type: mimeType });
        const ext      = mimeType.includes("ogg") ? "ogg" : "webm";
        const ts       = new Date().toISOString().replace(/[:.]/g, "-");
        const file     = new File([blob], `voice-message-${ts}.${ext}`, { type: mimeType });

        _chunks = [];
        if (_onComplete) _onComplete(file, Math.round(duration));
    }

    function _animateLevel() {
        if (!_analyser) return;
        const buf = new Uint8Array(_analyser.frequencyBinCount);
        const tick = () => {
            if (!_analyser) return;
            _analyser.getByteFrequencyData(buf);
            const avg = buf.reduce((s, v) => s + v, 0) / buf.length;
            if (_onLevel) _onLevel(avg / 255);
            requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
    }

    function _cleanup() {
        if (_stream) { _stream.getTracks().forEach(t => t.stop()); _stream = null; }
        if (_audioCtx) { _audioCtx.close(); _audioCtx = null; }
        _analyser      = null;
        _mediaRecorder = null;
        clearInterval(_timerInterval);
    }

    function isRecording() {
        return !!_mediaRecorder && _mediaRecorder.state === "recording";
    }

    return { start, stop, cancel, onTick, onLevel, onComplete, onCancel, isRecording };
})();


// ── VoiceMessageUI ────────────────────────────────────────────────

const VoiceMessageUI = (() => {

    // Mount recording controls into container.
    // onSend(file, durationSeconds) — called when recording is done.
    function mount(container, onSend) {
        container.innerHTML = _buildHTML();

        const recordBtn  = container.querySelector("#vmRecordBtn");
        const stopBtn    = container.querySelector("#vmStopBtn");
        const cancelBtn  = container.querySelector("#vmCancelBtn");
        const canvas     = container.querySelector("#vmWaveform");
        const timer      = container.querySelector("#vmTimer");
        const status     = container.querySelector("#vmStatus");
        const ctx        = canvas.getContext("2d");
        const levels     = new Array(40).fill(0);

        VoiceRecorder.onTick(s => {
            const m   = Math.floor(s / 60);
            const sec = String(Math.floor(s % 60)).padStart(2, "0");
            timer.textContent = `${m}:${sec}`;
        });

        VoiceRecorder.onLevel(level => {
            levels.shift();
            levels.push(level);
            _drawWaveform(ctx, canvas, levels);
        });

        VoiceRecorder.onComplete(async (file, duration) => {
            status.textContent    = "Sending…";
            recordBtn.style.display  = "flex";
            stopBtn.style.display    = "none";
            cancelBtn.style.display  = "none";
            timer.textContent = "0:00";
            _clearWaveform(ctx, canvas);
            try {
                await onSend(file, duration);
                status.textContent = "";
            } catch (e) {
                status.textContent = "Failed to send";
                console.error("[VoiceMsg] send error", e);
            }
        });

        VoiceRecorder.onCancel(() => {
            recordBtn.style.display  = "flex";
            stopBtn.style.display    = "none";
            cancelBtn.style.display  = "none";
            timer.textContent = "0:00";
            status.textContent = "";
            _clearWaveform(ctx, canvas);
        });

        recordBtn.onclick = async () => {
            try {
                await VoiceRecorder.start();
                recordBtn.style.display  = "none";
                stopBtn.style.display    = "flex";
                cancelBtn.style.display  = "flex";
                status.textContent = "Recording…";
            } catch (e) {
                status.textContent = "Microphone access denied";
            }
        };

        stopBtn.onclick   = () => VoiceRecorder.stop();
        cancelBtn.onclick = () => VoiceRecorder.cancel();
    }

    function _buildHTML() {
        return `<div class="vm-recorder">
  <button id="vmRecordBtn" class="vm-btn vm-btn-record" type="button"
          aria-label="Record voice message" style="display:flex">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
         stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
      <path d="M19 10v2a7 7 0 0 1-14 0v-2"/>
      <line x1="12" y1="19" x2="12" y2="23"/>
      <line x1="8"  y1="23" x2="16" y2="23"/>
    </svg>
  </button>
  <button id="vmStopBtn" class="vm-btn vm-btn-stop" type="button"
          aria-label="Stop recording" style="display:none">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <rect x="3" y="3" width="18" height="18" rx="2"/>
    </svg>
  </button>
  <button id="vmCancelBtn" class="vm-btn vm-btn-cancel" type="button"
          aria-label="Cancel recording" style="display:none">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
         stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <line x1="18" y1="6" x2="6" y2="18"/>
      <line x1="6"  y1="6" x2="18" y2="18"/>
    </svg>
  </button>
  <canvas id="vmWaveform" width="120" height="32" class="vm-waveform" aria-hidden="true"></canvas>
  <span id="vmTimer" class="vm-timer" aria-live="polite">0:00</span>
  <span id="vmStatus" class="vm-status" aria-live="polite"></span>
</div>`;
    }

    function _drawWaveform(ctx, canvas, levels) {
        const w = canvas.width, h = canvas.height;
        ctx.clearRect(0, 0, w, h);
        const barW = w / levels.length - 1;
        const color = getComputedStyle(document.documentElement)
            .getPropertyValue("--accent").trim() || "#2563eb";
        levels.forEach((level, i) => {
            const barH = Math.max(2, level * h);
            const x    = i * (barW + 1);
            const y    = (h - barH) / 2;
            ctx.fillStyle = color;
            ctx.beginPath();
            if (ctx.roundRect) {
                ctx.roundRect(x, y, barW, barH, 2);
            } else {
                ctx.rect(x, y, barW, barH);
            }
            ctx.fill();
        });
    }

    function _clearWaveform(ctx, canvas) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
    }

    return { mount };
})();


// ── VoiceMessageBubble ────────────────────────────────────────────

const VoiceMessageBubble = (() => {

    const _playing = new Map();   // fileId → HTMLAudioElement
    let _decryptFn = null;        // set via setDecryptFn — avoids global FileE2EE dependency

    // Call this from chat.js to wire up the decryption pipeline:
    //   VoiceMessageBubble.setDecryptFn((fileId, cb) => FileE2EE.downloadAndDecrypt(fileId, cb))
    function setDecryptFn(fn) { _decryptFn = fn; }

    function renderBubble(fileId, durationSeconds) {
        const id  = `vmPlay_${fileId}`;
        const dur = _fmtDuration(durationSeconds || 0);

        return `<div class="vm-bubble" data-file-id="${fileId}">
  <button class="vm-play-btn" id="${id}_btn"
          type="button"
          onclick="VoiceMessageBubble.toggle(${fileId})"
          aria-label="Play voice message">
    <svg id="${id}_icon" width="14" height="14" viewBox="0 0 24 24"
         fill="currentColor" aria-hidden="true">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  </button>
  <div class="vm-progress-wrap">
    <div class="vm-progress-bar" id="${id}_bar"></div>
  </div>
  <span class="vm-duration" id="${id}_dur">${dur}</span>
  <svg class="vm-enc-badge" width="11" height="11" viewBox="0 0 24 24"
       fill="currentColor" title="End-to-end encrypted"
       aria-label="Encrypted" aria-hidden="true">
    <path d="M18 8h-1V6A5 5 0 0 0 7 6v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12
             a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2zm-6 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm3-9H9V6
             a3 3 0 0 1 6 0v2z"/>
  </svg>
</div>`;
    }

    async function toggle(fileId) {
        const id    = `vmPlay_${fileId}`;
        const btn   = document.getElementById(`${id}_btn`);
        const icon  = document.getElementById(`${id}_icon`);
        const bar   = document.getElementById(`${id}_bar`);
        const durEl = document.getElementById(`${id}_dur`);

        if (!btn || !icon) return;

        const existing = _playing.get(fileId);
        if (existing && !existing.paused) {
            existing.pause();
            _setPlayIcon(icon);
            return;
        }
        if (existing && existing.paused) {
            existing.play();
            _setPauseIcon(icon);
            return;
        }

        _setLoadingIcon(icon);
        btn.disabled = true;

        if (!_decryptFn) {
            icon.innerHTML = _alertIcon();
            btn.disabled = false;
            console.error("[VoiceMsg] decryptFn not set — call VoiceMessageBubble.setDecryptFn()");
            return;
        }

        try {
            await new Promise((resolve, reject) => {
                const p = _decryptFn(fileId, (url, filename, mimeType) => {
                    const audio = new Audio(url);
                    _playing.set(fileId, audio);

                    audio.ontimeupdate = () => {
                        const pct = audio.currentTime / audio.duration * 100;
                        if (bar) bar.style.width = pct + "%";
                        if (durEl) durEl.textContent = _fmtDuration(
                            Math.floor(audio.duration - audio.currentTime)
                        );
                    };

                    audio.onended = () => {
                        _setPlayIcon(icon);
                        if (bar) bar.style.width = "0%";
                        _playing.delete(fileId);
                        URL.revokeObjectURL(url);
                    };

                    audio.onerror = () => {
                        icon.innerHTML = _alertIcon();
                        btn.disabled = false;
                        _playing.delete(fileId);
                        reject(new Error("audio error"));
                    };

                    btn.disabled = false;
                    _setPauseIcon(icon);
                    audio.play().then(resolve).catch(reject);
                });
                // catch network/decrypt errors from _decryptFn itself
                if (p && typeof p.catch === "function") p.catch(reject);
            });
        } catch (e) {
            console.error("[VoiceMsg] decrypt/play error", e);
            icon.innerHTML = _alertIcon();
            btn.disabled = false;
        }
    }

    function _fmtDuration(s) {
        const m   = Math.floor(s / 60);
        const sec = String(Math.floor(s % 60)).padStart(2, "0");
        return `${m}:${sec}`;
    }

    function _setPlayIcon(icon) {
        icon.innerHTML = '<polygon points="5 3 19 12 5 21 5 3"/>';
        icon.setAttribute("viewBox", "0 0 24 24");
        icon.setAttribute("fill", "currentColor");
        icon.removeAttribute("stroke");
    }

    function _setPauseIcon(icon) {
        icon.innerHTML = '<line x1="6" y1="4" x2="6" y2="20"/><line x1="18" y1="4" x2="18" y2="20"/>';
        icon.setAttribute("viewBox", "0 0 24 24");
        icon.setAttribute("fill", "none");
        icon.setAttribute("stroke", "currentColor");
        icon.setAttribute("stroke-width", "2");
        icon.setAttribute("stroke-linecap", "round");
    }

    function _setLoadingIcon(icon) {
        icon.innerHTML = '<circle cx="12" cy="12" r="10" stroke-dasharray="31.4" stroke-dashoffset="10" stroke="currentColor" fill="none" stroke-width="2"/>';
        icon.setAttribute("viewBox", "0 0 24 24");
        icon.setAttribute("fill", "none");
        icon.removeAttribute("stroke");
    }

    function _alertIcon() {
        return '<line x1="12" y1="8" x2="12" y2="12" stroke="currentColor" stroke-width="2"/>' +
               '<line x1="12" y1="16" x2="12.01" y2="16" stroke="currentColor" stroke-width="2"/>' +
               '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="currentColor" stroke-width="2" fill="none"/>';
    }

    return { renderBubble, toggle, setDecryptFn };
})();
