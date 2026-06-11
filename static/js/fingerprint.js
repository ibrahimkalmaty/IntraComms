// fingerprint.js
// Key fingerprint verification for IntraComms
//
// A fingerprint is SHA-256(SPKI public key bytes), displayed as the
// first 20 bytes in grouped hex — same convention as Signal.
//
// Verification state lives in localStorage only. The server never
// knows about it and therefore cannot fake or suppress it.
// A mismatch fires when the server returns a different key than the
// one the user previously verified — detecting a server-side key swap.

var Fingerprint = (function () {
    var VERIFIED_KEY = "intracomms_verified_keys_v1";
    var KNOWN_KEY    = "intracomms_known_keys_v1";

    // ── Helpers ──────────────────────────────────────────────────────
    function _b64ToBuffer(b64) {
        var bin = atob(b64);
        var buf = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        return buf.buffer;
    }

    function _esc(str) {
        return String(str)
            .replace(/&/g, "&amp;").replace(/</g, "&lt;")
            .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    function _formatFingerprint(bytes) {
        var hex = Array.prototype.map.call(bytes, function (b) {
            return b.toString(16).padStart(2, "0");
        });
        var groups = [];
        for (var i = 0; i < hex.length; i += 4) groups.push(hex.slice(i, i + 4).join(" "));
        return groups.join("  ·  ");
    }

    function _loadVerified() {
        try { return JSON.parse(localStorage.getItem(VERIFIED_KEY) || "{}"); } catch (_) { return {}; }
    }
    function _saveVerified(d) { localStorage.setItem(VERIFIED_KEY, JSON.stringify(d)); }
    function _loadKnown() {
        try { return JSON.parse(localStorage.getItem(KNOWN_KEY) || "{}"); } catch (_) { return {}; }
    }
    function _saveKnown(d) { localStorage.setItem(KNOWN_KEY, JSON.stringify(d)); }

    // ── SVG icons ─────────────────────────────────────────────────────
    function _svg(path, color, size) {
        size = size || 14;
        return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="none"'
             + ' stroke="' + color + '" stroke-width="2.2" stroke-linecap="round"'
             + ' stroke-linejoin="round" aria-hidden="true">' + path + '</svg>';
    }
    var _SHIELD = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>';
    var _CHECK  = '<polyline points="20 6 9 17 4 12"/>';
    var _X      = '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>';
    var _WARN   = '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';

    // ── Core: compute fingerprint from base64-SPKI public key ─────────
    function compute(publicKeyB64) {
        if (!publicKeyB64 || !window.crypto || !window.crypto.subtle) return Promise.resolve(null);
        return crypto.subtle.digest("SHA-256", _b64ToBuffer(publicKeyB64)).then(function (hashBuf) {
            return _formatFingerprint(new Uint8Array(hashBuf).slice(0, 20));
        });
    }

    // ── Record that we've seen a key from the server ───────────────────
    // Call this every time a public key is fetched from /api/users/<id>/pubkey
    function recordSeen(userId, publicKeyB64) {
        var uid = String(userId);
        return compute(publicKeyB64).then(function (fp) {
            if (!fp) return fp;
            var known    = _loadKnown();
            var previous = known[uid];
            known[uid]   = fp;
            _saveKnown(known);

            var verified = _loadVerified();
            if (verified[uid] && verified[uid].fingerprint !== fp) {
                _triggerMismatch(uid, previous, fp);
            }
            return fp;
        });
    }

    // ── Verification state ─────────────────────────────────────────────
    function markVerified(userId, fingerprint) {
        var uid      = String(userId);
        var verified = _loadVerified();
        verified[uid] = { fingerprint: fingerprint, verifiedAt: new Date().toISOString() };
        _saveVerified(verified);
        _updateUI(uid);
    }

    function markUnverified(userId) {
        var uid      = String(userId);
        var verified = _loadVerified();
        delete verified[uid];
        _saveVerified(verified);
        _updateUI(uid);
    }

    // Returns "verified" | "unverified" | "mismatch"
    function getState(userId) {
        var uid      = String(userId);
        var verified = _loadVerified();
        var known    = _loadKnown();
        if (!verified[uid]) return "unverified";
        if (verified[uid].fingerprint !== known[uid]) return "mismatch";
        return "verified";
    }

    function getKnown(userId) { return _loadKnown()[String(userId)] || null; }

    function getOwn(pubKeyB64) {
        if (!pubKeyB64) return Promise.resolve(null);
        return compute(pubKeyB64);
    }

    // ── Events ────────────────────────────────────────────────────────
    function _triggerMismatch(userId, oldFp, newFp) {
        document.dispatchEvent(new CustomEvent("fingerprint:mismatch", {
            detail: { userId: userId, oldFp: oldFp, newFp: newFp }
        }));
    }

    function _updateUI(userId) {
        document.dispatchEvent(new CustomEvent("fingerprint:updated", {
            detail: { userId: String(userId), state: getState(userId) }
        }));
    }

    // ── Inline badge (HTML string) for direct-chat header ─────────────
    function inlineBadge(userId) {
        var state = getState(String(userId));
        var uid   = String(userId);
        if (state === "verified") {
            return '<button class="fp-badge-btn fp-badge-verified"'
                 + ' onclick="Fingerprint.showModal(' + uid + ')" title="Identity verified · click to manage"'
                 + ' aria-label="Identity verified">'
                 + _svg(_SHIELD + _CHECK, "#059669", 15) + '</button>';
        }
        if (state === "mismatch") {
            return '<button class="fp-badge-btn fp-badge-mismatch"'
                 + ' onclick="Fingerprint.showModal(' + uid + ')" title="Key mismatch — verify again"'
                 + ' aria-label="Key mismatch">'
                 + _svg(_SHIELD + _WARN, "#dc2626", 15) + '</button>';
        }
        return '<button class="fp-badge-btn fp-badge-unverified"'
             + ' onclick="Fingerprint.showModal(' + uid + ')" title="Not verified · click to verify"'
             + ' aria-label="Not verified">'
             + _svg(_SHIELD, "#94a3b8", 15) + '</button>';
    }

    // ── Verify modal ──────────────────────────────────────────────────
    function showModal(userId) {
        var uid      = String(userId);
        var fp       = getKnown(uid);
        var state    = getState(uid);

        var username = (function () {
            var row = document.querySelector('[data-chat-id="' + uid + '"]');
            return row ? (row.dataset.chatName || "User") : "User";
        })();

        var overlay = document.getElementById("fp-modal-overlay");
        if (!overlay) {
            overlay = document.createElement("div");
            overlay.id = "fp-modal-overlay";
            overlay.className = "fp-modal-overlay";
            overlay.addEventListener("click", function (e) {
                if (e.target === overlay) closeModal();
            });
            document.body.appendChild(overlay);
        }
        // ESC to close
        overlay._keyHandler && document.removeEventListener("keydown", overlay._keyHandler);
        overlay._keyHandler = function (e) { if (e.key === "Escape") closeModal(); };
        document.addEventListener("keydown", overlay._keyHandler);

        var stateBadge = {
            verified:   '<span class="fp-state-badge fp-state-verified">Verified</span>',
            unverified: '<span class="fp-state-badge fp-state-unverified">Not verified</span>',
            mismatch:   '<span class="fp-state-badge fp-state-mismatch">Key changed</span>',
        }[state];

        var mismatchWarn = state === "mismatch"
            ? '<div class="fp-mismatch-warn">'
              + _svg(_WARN, "#991b1b", 14) + ' '
              + "Their key changed since you last verified. Do not send sensitive messages until you have re-verified this fingerprint with them directly."
              + '</div>'
            : "";

        var fpBlock = fp
            ? '<div class="fp-hex">' + _esc(fp) + '</div>'
            : '<div class="fp-hex fp-hex-unknown">Fingerprint not yet available — send a message first to fetch their key.</div>';

        var actionBtn = state === "verified"
            ? '<button class="btn btn-outline-secondary btn-sm" onclick="Fingerprint.markUnverified(' + uid + ');Fingerprint.showModal(' + uid + ')">Remove verification</button>'
            : fp
                ? '<button class="btn btn-primary btn-sm" onclick="Fingerprint._doVerify(' + uid + ',\'' + fp.replace(/'/g, "\\'") + '\')">Mark as verified</button>'
                : '';

        overlay.innerHTML =
            '<div class="fp-modal" role="dialog" aria-modal="true" aria-label="Verify identity">' +
            '  <div class="fp-modal-header">' +
            '    <div class="fp-modal-title">' + _svg(_SHIELD, "#64748b", 16) +
            '      <strong>' + _esc(username) + '</strong>' + stateBadge +
            '    </div>' +
            '    <button class="fp-modal-close" onclick="Fingerprint.closeModal()" aria-label="Close">' +
            '      ' + _svg(_X, "#64748b", 16) + '</button>' +
            '  </div>' +
            mismatchWarn +
            '  <p class="fp-hint">Compare this code with <strong>' + _esc(username) + '</strong> in person or on a call.' +
            '  If it matches on both devices, your messages are private and cannot be read by the server.</p>' +
            fpBlock +
            '  <div class="fp-actions">' + actionBtn + '</div>' +
            '</div>';

        overlay.hidden = false;
        overlay.style.display = "flex";
    }

    function closeModal() {
        var overlay = document.getElementById("fp-modal-overlay");
        if (!overlay) return;
        overlay.hidden = true;
        overlay.style.display = "none";
        overlay._keyHandler && document.removeEventListener("keydown", overlay._keyHandler);
    }

    function _doVerify(userId, fingerprint) {
        markVerified(String(userId), fingerprint);
        showModal(String(userId)); // re-render to show new state
    }

    return {
        compute:       compute,
        recordSeen:    recordSeen,
        markVerified:  markVerified,
        markUnverified: markUnverified,
        getState:      getState,
        getKnown:      getKnown,
        getOwn:        getOwn,
        inlineBadge:   inlineBadge,
        showModal:     showModal,
        closeModal:    closeModal,
        _doVerify:     _doVerify,
    };
})();
