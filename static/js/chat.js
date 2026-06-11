(function () {
    "use strict";

    /* ── DOM refs ── */
    const dataEl         = document.getElementById("chat-data");
    const form           = document.getElementById("chat-form");
    const list           = document.getElementById("message-list");
    const statusEl       = document.getElementById("chat-status");
    const contentEl      = document.getElementById("content");
    const receiverEl     = document.getElementById("receiver_id");
    const charCountEl    = document.getElementById("character-count");
    const sendBtn        = document.getElementById("send-btn");
    const chatSearchEl    = document.getElementById("chat-search");
    const contactSearchEl = document.getElementById("contact-search");
    const backBtn         = document.getElementById("back-btn");
    const railEl          = document.querySelector(".conversation-rail");
    const panelEl         = document.querySelector(".chat-panel");
    const attachBtn       = document.getElementById("attach-btn");
    const fileInputEl     = document.getElementById("file-input");
    const chatTitleEl    = document.getElementById("chat-title");
    const chatSubtitleEl = document.getElementById("chat-subtitle");
    const chatAvatarEl   = document.getElementById("chat-avatar");
    const chatContextEl  = document.getElementById("chat-context");
    const emptyChatEl    = document.getElementById("empty-chat-state");
    const convRows       = document.querySelectorAll(".conversation-row[data-chat-id]");

    if (!dataEl || !form || !list || !window.WebSocket) return;

    const currentUserId = Number(dataEl.dataset.currentUserId);
    const AVATAR_COLORS = ["avatar-c0","avatar-c1","avatar-c2","avatar-c3",
                           "avatar-c4","avatar-c5","avatar-c6","avatar-c7"];

    // Public keys of every other user keyed by user_id string.
    // Populated from the server-rendered data attribute; updated live when
    // a new-message payload arrives with a recipient who now has a key.
    var userPubkeys = {};
    try { userPubkeys = JSON.parse(dataEl.dataset.userPubkeys || "{}"); } catch (_) {}

    /* ── E2EE module ─────────────────────────────────────────────────────────
     *
     * Design mirrors e2ee_protocol.py exactly, but runs in the browser:
     *   Identity keys    : ECDH P-256 (Web Crypto — broad browser support)
     *   Key encapsulation: ECIES — ephemeral DH per message → shared secret
     *   Symmetric cipher : AES-256-GCM (IND-CCA, confidentiality + integrity)
     *   KDF              : HKDF-SHA-256 (via SubtleCrypto deriveKey with ECDH)
     *   PRNG             : crypto.getRandomValues (CSPRNG)
     *
     * Private key is stored as JWK in localStorage so it survives page reloads.
     * The public key (SPKI, base64) is registered with the server on every
     * page load so other users can always encrypt for us.
     *
     * Broadcast messages are NOT encrypted (no per-recipient E2EE possible
     * without a ratchet protocol; they are public by nature anyway).
     * ─────────────────────────────────────────────────────────────────────── */
    var E2EE = (function () {
        var STORAGE_KEY = "intracomms_priv_jwk_v1";
        var _privateKey    = null;   // CryptoKey — never leaves this closure
        var _pubKeyB64     = null;   // base64-SPKI — safe to share with server
        var _ready         = false;
        var _readyWaiters  = [];     // resolve callbacks queued before init()

        function _ab2b64(buf) {
            return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
        }
        function _b642ab(b64) {
            var bin = atob(b64), arr = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
            return arr.buffer;
        }

        function _markReady() {
            _ready = true;
            _readyWaiters.forEach(function (fn) { fn(); });
            _readyWaiters = [];
        }

        /* Public: resolves immediately if already ready, otherwise waits. */
        function whenReady() {
            if (_ready) return Promise.resolve();
            return new Promise(function (resolve) { _readyWaiters.push(resolve); });
        }

        function isReady() { return _ready; }
        function isCryptoAvailable() { return !!(window.crypto && window.crypto.subtle); }

        /* Generate a fresh ECDH P-256 keypair and persist the private key. */
        function _generateAndStore() {
            return crypto.subtle.generateKey(
                { name: "ECDH", namedCurve: "P-256" },
                true,           // extractable so we can persist as JWK
                ["deriveKey"]
            ).then(function (kp) {
                _privateKey = kp.privateKey;
                return Promise.all([
                    crypto.subtle.exportKey("jwk",  kp.privateKey),
                    crypto.subtle.exportKey("spki", kp.publicKey),
                ]);
            }).then(function (results) {
                var jwk    = results[0];
                var spkiBuf = results[1];
                try { localStorage.setItem(STORAGE_KEY, JSON.stringify(jwk)); } catch (_) {}
                _pubKeyB64 = _ab2b64(spkiBuf);
            });
        }

        /* Load an existing keypair from localStorage. */
        function _loadFromStorage(jwk) {
            // Import private key
            return crypto.subtle.importKey(
                "jwk", jwk,
                { name: "ECDH", namedCurve: "P-256" },
                false,          // not extractable — it's already persisted
                ["deriveKey"]
            ).then(function (privKey) {
                _privateKey = privKey;
                // Reconstruct public key from JWK's x/y fields (P-256 convention)
                var pubJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true };
                return crypto.subtle.importKey(
                    "jwk", pubJwk,
                    { name: "ECDH", namedCurve: "P-256" },
                    true, []
                );
            }).then(function (pubKey) {
                return crypto.subtle.exportKey("spki", pubKey);
            }).then(function (spkiBuf) {
                _pubKeyB64 = _ab2b64(spkiBuf);
            });
        }

        /* Register our public key with the server (called on every page load). */
        function _registerPubkey() {
            return fetch("/api/me/pubkey", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ public_key: _pubKeyB64 }),
            }).catch(function () {});
        }

        /* ── Key backup / restore ──────────────────────────────────────────── */

        function _getIekBuf() {
            try {
                var b64 = sessionStorage.getItem("_iek");
                return b64 ? _b642ab(b64) : null;
            } catch (_) { return null; }
        }

        function _deriveIek(password, username) {
            var enc = new TextEncoder();
            return crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"])
                .then(function (km) {
                    return crypto.subtle.deriveBits(
                        { name: "PBKDF2", salt: enc.encode("intracomms:v1:" + username),
                          iterations: 100000, hash: "SHA-256" },
                        km, 256
                    );
                });
        }

        function _uploadKeyBackup(iekBuf) {
            var stored = localStorage.getItem(STORAGE_KEY);
            if (!stored || !iekBuf) return Promise.resolve();
            var iv = crypto.getRandomValues(new Uint8Array(12));
            return crypto.subtle.importKey("raw", iekBuf, { name: "AES-GCM" }, false, ["encrypt"])
                .then(function (key) {
                    return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key,
                        new TextEncoder().encode(stored));
                }).then(function (enc) {
                    return fetch("/api/me/key-backup", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ encrypted: _ab2b64(enc), salt: _ab2b64(iv) }),
                    });
                }).catch(function () {});
        }

        function _decryptAndRestoreKey(encB64, ivB64, iekBuf) {
            return crypto.subtle.importKey("raw", iekBuf, { name: "AES-GCM" }, false, ["decrypt"])
                .then(function (key) {
                    return crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: new Uint8Array(_b642ab(ivB64)) },
                        key, _b642ab(encB64)
                    );
                }).then(function (plain) {
                    var jwk = JSON.parse(new TextDecoder().decode(plain));
                    localStorage.setItem(STORAGE_KEY, JSON.stringify(jwk));
                    return _loadFromStorage(jwk);
                });
        }

        function _promptPasswordAndRestore(backupData) {
            var dataEl   = document.getElementById("chat-data");
            var username = dataEl ? (dataEl.dataset.currentUsername || "") : "";
            return new Promise(function (resolve) {
                var overlay = document.createElement("div");
                overlay.className = "key-restore-overlay";
                overlay.innerHTML =
                    '<div class="key-restore-modal">' +
                    '<h3>Restore Encryption Key</h3>' +
                    '<p>Enter your password to read encrypted messages on this device.</p>' +
                    '<input type="password" id="_kr-pwd" placeholder="Your password" autocomplete="current-password">' +
                    '<div class="key-restore-err" id="_kr-err"></div>' +
                    '<div class="key-restore-actions">' +
                    '<button id="_kr-skip">Skip (generate new key)</button>' +
                    '<button id="_kr-ok" class="key-restore-primary">Restore</button>' +
                    '</div></div>';
                document.body.appendChild(overlay);

                var pwdEl = overlay.querySelector("#_kr-pwd");
                var errEl = overlay.querySelector("#_kr-err");

                function tryRestore() {
                    var pwd = pwdEl.value;
                    if (!pwd) return;
                    errEl.textContent = "";
                    _deriveIek(pwd, username)
                        .then(function (iekBuf) {
                            return _decryptAndRestoreKey(backupData.encrypted, backupData.salt, iekBuf)
                                .then(function () {
                                    sessionStorage.setItem("_iek", _ab2b64(iekBuf));
                                });
                        })
                        .then(function () { overlay.remove(); resolve(); })
                        .catch(function () {
                            errEl.textContent = "Incorrect password — try again.";
                            pwdEl.value = "";
                            pwdEl.focus();
                        });
                }

                overlay.querySelector("#_kr-ok").addEventListener("click", tryRestore);
                overlay.querySelector("#_kr-skip").addEventListener("click", function () {
                    overlay.remove();
                    _generateAndStore().then(function () {
                        return _uploadKeyBackup(_getIekBuf());
                    }).then(resolve);
                });
                pwdEl.addEventListener("keydown", function (e) { if (e.key === "Enter") tryRestore(); });
                setTimeout(function () { pwdEl.focus(); }, 50);
            });
        }

        function _ensureKeyBackedUp() {
            var iekBuf = _getIekBuf();
            if (!iekBuf) return Promise.resolve();
            return fetch("/api/me/key-backup")
                .then(function (r) { return r.json(); })
                .then(function (data) { if (!data.available) return _uploadKeyBackup(iekBuf); })
                .catch(function () {});
        }

        function _restoreOrGenerate() {
            return fetch("/api/me/key-backup")
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (!data.available) {
                        return _generateAndStore().then(_ensureKeyBackedUp);
                    }
                    var iekBuf = _getIekBuf();
                    if (iekBuf) {
                        return _decryptAndRestoreKey(data.encrypted, data.salt, iekBuf)
                            .catch(function () {
                                return _generateAndStore().then(function () {
                                    return _uploadKeyBackup(_getIekBuf());
                                });
                            });
                    }
                    return _promptPasswordAndRestore(data);
                })
                .catch(function () { return _generateAndStore(); });
        }

        /* Initialise: load or generate keypair, then register. */
        function init() {
            if (!window.crypto || !window.crypto.subtle) {
                console.warn("[E2EE] SubtleCrypto unavailable — encryption disabled.");
                _markReady();
                return Promise.resolve();
            }

            var stored = null;
            try { stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null"); } catch (_) {}

            var p = stored
                ? _loadFromStorage(stored)
                    .catch(function () {
                        localStorage.removeItem(STORAGE_KEY);
                        return _generateAndStore();
                    })
                    .then(_ensureKeyBackedUp)
                : _restoreOrGenerate();

            return p.then(_registerPubkey).then(_markReady).catch(function (err) {
                console.error("[E2EE] init failed:", err);
                _markReady();
            });
        }

        /* ── ECIES encrypt ──────────────────────────────────────────────────
         *  1. Import recipient's long-term public key (SPKI base64)
         *  2. Generate ephemeral ECDH keypair — discarded after this call
         *  3. DH(ephemeral_private, recipient_public) → raw shared secret
         *  4. deriveKey (AES-256-GCM) via SubtleCrypto HKDF-like derivation
         *  5. AES-GCM encrypt with a fresh 12-byte CSPRNG nonce
         *  6. Return { ephemeral_pub, iv, ciphertext } — all base64
         * ─────────────────────────────────────────────────────────────────── */
        function encryptFor(recipientPubB64, plaintext) {
            if (!_privateKey) return Promise.reject(new Error("E2EE not ready"));

            var recipientPub;
            return crypto.subtle.importKey(
                "spki", _b642ab(recipientPubB64),
                { name: "ECDH", namedCurve: "P-256" },
                false, []
            ).then(function (pub) {
                recipientPub = pub;
                return crypto.subtle.generateKey(
                    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
                );
            }).then(function (ephemeral) {
                // Derive a non-extractable AES-256-GCM key from the shared secret
                var aesKeyPromise = crypto.subtle.deriveKey(
                    { name: "ECDH", public: recipientPub },
                    ephemeral.privateKey,
                    { name: "AES-GCM", length: 256 },
                    false,
                    ["encrypt"]
                );
                var ephPubPromise = crypto.subtle.exportKey("spki", ephemeral.publicKey);
                return Promise.all([aesKeyPromise, ephPubPromise]);
            }).then(function (results) {
                var aesKey      = results[0];
                var ephPubSpki  = results[1];
                var iv          = crypto.getRandomValues(new Uint8Array(12));
                var enc         = new TextEncoder();
                return Promise.all([
                    crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, enc.encode(plaintext)),
                    Promise.resolve(ephPubSpki),
                    Promise.resolve(iv),
                ]);
            }).then(function (results) {
                return {
                    ciphertext:   _ab2b64(results[0]),
                    ephemeral_pub: _ab2b64(results[1]),
                    iv:           _ab2b64(results[2]),
                };
            });
        }

        /* ── ECIES decrypt ──────────────────────────────────────────────────
         *  1. Import the ephemeral public key from the packet
         *  2. DH(our_private, ephemeral_public) → same shared secret
         *  3. Derive same AES key
         *  4. AES-GCM decrypt + authenticate — raises on tamper
         *  Returns decrypted string, or null on any failure.
         * ─────────────────────────────────────────────────────────────────── */
        function decrypt(ephemeralPubB64, ivB64, ciphertextB64) {
            if (!_privateKey) return Promise.resolve(null);
            if (!ephemeralPubB64 || ephemeralPubB64 === "plain-text-prototype") {
                return Promise.resolve(null);
            }
            return crypto.subtle.importKey(
                "spki", _b642ab(ephemeralPubB64),
                { name: "ECDH", namedCurve: "P-256" },
                false, []
            ).then(function (ephPub) {
                return crypto.subtle.deriveKey(
                    { name: "ECDH", public: ephPub },
                    _privateKey,
                    { name: "AES-GCM", length: 256 },
                    false,
                    ["decrypt"]
                );
            }).then(function (aesKey) {
                return crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: new Uint8Array(_b642ab(ivB64)) },
                    aesKey,
                    _b642ab(ciphertextB64)
                );
            }).then(function (plain) {
                return new TextDecoder().decode(plain);
            }).catch(function () {
                return null; // tampered, wrong key, or non-E2EE content
            });
        }

        function getMyPubKey() { return _pubKeyB64; }

        /* Like decrypt() but returns the raw ArrayBuffer instead of a string.
           Used by FileE2EE to unseal a file key. */
        function decryptRaw(ephemeralPubB64, ivB64, ciphertextB64) {
            if (!_privateKey) return Promise.reject(new Error("E2EE not ready"));
            return crypto.subtle.importKey(
                "spki", _b642ab(ephemeralPubB64),
                { name: "ECDH", namedCurve: "P-256" }, false, []
            ).then(function (ephPub) {
                return crypto.subtle.deriveKey(
                    { name: "ECDH", public: ephPub },
                    _privateKey,
                    { name: "AES-GCM", length: 256 }, false, ["decrypt"]
                );
            }).then(function (aesKey) {
                return crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: new Uint8Array(_b642ab(ivB64)) },
                    aesKey,
                    _b642ab(ciphertextB64)
                );
            });
        }

        function getPrivateKey() { return _privateKey; }

        return { init: init, whenReady: whenReady, isReady: isReady,
                 isCryptoAvailable: isCryptoAvailable,
                 encryptFor: encryptFor, decrypt: decrypt, decryptRaw: decryptRaw,
                 getMyPubKey: getMyPubKey, getPrivateKey: getPrivateKey };
    })();

    /* ── FileE2EE — client-side file encryption ──────────────────────────────
     * Non-video direct uploads are encrypted here before leaving the browser.
     * Video stays plaintext for server-side transcoding, then is encrypted at
     * rest by the server (key sealed with the recipient's public key).
     * ────────────────────────────────────────────────────────────────────── */
    var FileE2EE = (function () {
        function _ab2b64(buf) {
            return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
        }
        function _b642ab(b64) {
            var bin = atob(b64), a = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
            return a.buffer;
        }

        /* ECIES-seal a raw key buffer for one recipient public key. */
        function _sealKey(keyRawBuf, recipientPubB64) {
            var iv = crypto.getRandomValues(new Uint8Array(12));
            var recipPub, ephKp;
            return crypto.subtle.importKey(
                "spki", _b642ab(recipientPubB64),
                { name: "ECDH", namedCurve: "P-256" }, false, []
            ).then(function (pub) {
                recipPub = pub;
                return crypto.subtle.generateKey(
                    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
                );
            }).then(function (kp) {
                ephKp = kp;
                return crypto.subtle.deriveKey(
                    { name: "ECDH", public: recipPub },
                    ephKp.privateKey,
                    { name: "AES-GCM", length: 256 }, false, ["encrypt"]
                );
            }).then(function (sharedKey) {
                return Promise.all([
                    crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, sharedKey, keyRawBuf),
                    crypto.subtle.exportKey("spki", ephKp.publicKey),
                ]);
            }).then(function (res) {
                return { sealed: _ab2b64(res[0]), ephPub: _ab2b64(res[1]), iv: _ab2b64(iv) };
            });
        }

        /* Encrypt a File object; returns an object with all upload fields.
           extraMeta: optional object merged into the encrypted meta (e.g. { duration }). */
        function encryptFile(file, recipientPubB64, senderPubB64, extraMeta) {
            var fileIv = crypto.getRandomValues(new Uint8Array(12));
            var fileKeyRaw, encryptedFile;
            return file.arrayBuffer().then(function (fileBuf) {
                return Promise.all([
                    Promise.resolve(fileBuf),
                    crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]),
                ]);
            }).then(function (res) {
                var fileBuf = res[0], fileKey = res[1];
                return Promise.all([
                    crypto.subtle.encrypt({ name: "AES-GCM", iv: fileIv }, fileKey, fileBuf),
                    crypto.subtle.exportKey("raw", fileKey),
                ]);
            }).then(function (res) {
                encryptedFile = res[0];
                fileKeyRaw    = res[1];
                var metaObj = Object.assign({ name: file.name, type: file.type, size: file.size }, extraMeta || {});
                var metaBytes = new TextEncoder().encode(JSON.stringify(metaObj));
                var metaIv = crypto.getRandomValues(new Uint8Array(12));
                return Promise.all([
                    _sealKey(fileKeyRaw, recipientPubB64),
                    senderPubB64 ? _sealKey(fileKeyRaw, senderPubB64) : Promise.resolve(null),
                    crypto.subtle.importKey("raw", fileKeyRaw, { name: "AES-GCM" }, false, ["encrypt"])
                        .then(function (fk) {
                            return crypto.subtle.encrypt({ name: "AES-GCM", iv: metaIv }, fk, metaBytes);
                        }).then(function (enc) {
                            return { data: _ab2b64(enc), iv: _ab2b64(metaIv) };
                        }),
                ]);
            }).then(function (res) {
                var forRecipient = res[0], forSender = res[1], encMeta = res[2];
                return {
                    encryptedBlob:         new Blob([encryptedFile]),
                    fileIv:                _ab2b64(fileIv),
                    sealedKey:             forRecipient.sealed,
                    keyEphemeralPub:       forRecipient.ephPub,
                    keyIv:                 forRecipient.iv,
                    senderSealedKey:       forSender ? forSender.sealed  : null,
                    senderKeyEphemeralPub: forSender ? forSender.ephPub  : null,
                    senderKeyIv:           forSender ? forSender.iv      : null,
                    encryptedMeta:         encMeta,
                };
            });
        }

        /* Encrypt + upload to /upload/e2ee. onProgress(pct) called during XHR.
           extraMeta: optional object merged into the encrypted metadata (e.g. { duration }). */
        function uploadEncryptedFile(file, receiverId, recipientPubB64, senderPubB64, onProgress, extraMeta) {
            return encryptFile(file, recipientPubB64, senderPubB64, extraMeta).then(function (enc) {
                return new Promise(function (resolve, reject) {
                    var fd = new FormData();
                    fd.append("file",                 enc.encryptedBlob, "encrypted");
                    fd.append("file_iv",              enc.fileIv);
                    fd.append("sealed_key",           enc.sealedKey);
                    fd.append("key_ephemeral_pub",    enc.keyEphemeralPub);
                    fd.append("key_iv",               enc.keyIv);
                    if (enc.senderSealedKey) {
                        fd.append("sender_sealed_key",     enc.senderSealedKey);
                        fd.append("sender_key_ephemeral",  enc.senderKeyEphemeralPub);
                        fd.append("sender_key_iv",         enc.senderKeyIv);
                    }
                    fd.append("encrypted_meta", JSON.stringify(enc.encryptedMeta));
                    fd.append("receiver_id",    String(receiverId));
                    var hintCat = file.type.startsWith("image/") ? "image"
                                : file.type.startsWith("video/") ? "video"
                                : file.type.startsWith("audio/") ? "audio" : "file";
                    fd.append("hint_category", hintCat);
                    fd.append("original_filename", file.name);

                    var xhr = new XMLHttpRequest();
                    if (onProgress) {
                        xhr.upload.addEventListener("progress", function (e) {
                            if (e.lengthComputable) onProgress(e.loaded, e.total);
                        });
                    }
                    xhr.addEventListener("load", function () {
                        if (xhr.status >= 200 && xhr.status < 300) {
                            resolve(JSON.parse(xhr.responseText));
                        } else {
                            var msg = "Upload failed";
                            try { msg = JSON.parse(xhr.responseText).error || msg; } catch (_) {}
                            reject(new Error(msg));
                        }
                    });
                    xhr.addEventListener("error", function () { reject(new Error("Network error")); });
                    xhr.open("POST", "/upload/e2ee");
                    xhr.send(fd);
                });
            });
        }

        /* Fetch /meta + /blob, decrypt, call onDecrypted(objectUrl, filename, mimeType). */
        function downloadAndDecrypt(fileId, onDecrypted) {
            var meta;
            return fetch("/uploads/" + fileId + "/meta").then(function (r) {
                if (!r.ok) throw new Error("meta fetch failed");
                return r.json();
            }).then(function (m) {
                meta = m;
                return fetch("/uploads/" + fileId + "/blob");
            }).then(function (r) {
                if (!r.ok) throw new Error("blob fetch failed");
                return r.arrayBuffer();
            }).then(function (blobBuf) {
                return E2EE.decryptRaw(meta.key_ephemeral_pub, meta.key_iv, meta.sealed_key)
                    .then(function (fileKeyRaw) {
                        return Promise.all([
                            Promise.resolve(blobBuf),
                            crypto.subtle.importKey("raw", fileKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]),
                        ]);
                    });
            }).then(function (res) {
                var blobBuf = res[0], fileKey = res[1];
                var fileIvBuf = new Uint8Array(_b642ab(meta.file_iv));
                var metaDecryptPromise = (meta.encrypted_meta)
                    ? crypto.subtle.decrypt(
                          { name: "AES-GCM", iv: new Uint8Array(_b642ab(meta.encrypted_meta.iv)) },
                          fileKey,
                          _b642ab(meta.encrypted_meta.data)
                      ).then(function (m) {
                          return JSON.parse(new TextDecoder().decode(m));
                      }).catch(function () { return null; })
                    : Promise.resolve(null);
                return Promise.all([
                    crypto.subtle.decrypt({ name: "AES-GCM", iv: fileIvBuf }, fileKey, blobBuf),
                    metaDecryptPromise,
                ]);
            }).then(function (res) {
                var decryptedBuf = res[0], fileMeta = res[1];
                var filename = (fileMeta && fileMeta.name) || "file";
                var mimeType = (fileMeta && fileMeta.type) || "application/octet-stream";
                var url = URL.createObjectURL(new Blob([decryptedBuf], { type: mimeType }));
                if (onDecrypted) onDecrypted(url, filename, mimeType);
            });
        }

        return { encryptFile: encryptFile, uploadEncryptedFile: uploadEncryptedFile,
                 downloadAndDecrypt: downloadAndDecrypt };
    })();


    let activeChatId   = "broadcast";
    let activeChatName = "Everyone";
    let onlineUsers    = new Set();   // user IDs currently connected
    let socket         = null;
    let connected      = false;
    let reconnectDelay = 1000;       // start at 1 s, doubles on each failure
    const MAX_DELAY    = 30000;      // cap at 30 s
    const messageQueue = [];         // offline buffer — flushed on reconnect
    let activeTab      = "chats";
    let connectionTier = "wifi_weak"; // safe default until measured
    let UPLOAD_CONFIG  = { video_chunk_size: 5 * 1024 * 1024, photo_compress: true };

    /* ── Connection quality measurement ── */
    function measureConnection() {
        var t0 = performance.now();
        fetch("/ping", { cache: "no-store" }).then(function () {
            var rtt = performance.now() - t0;
            var nav = navigator.connection || navigator.mozConnection || null;
            var down = nav ? nav.downlink : null;
            var tier;
            if (rtt < 5  && (!down || down > 50)) tier = "wired";
            else if (rtt < 20 && (!down || down > 20)) tier = "wifi_good";
            else if (rtt < 60 && (!down || down > 5))  tier = "wifi_weak";
            else tier = "slow";
            connectionTier = tier;
            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send("42" + JSON.stringify(["client_tier",
                    { tier: tier, rtt: rtt, downMbps: down }]));
            }
        }).catch(function () {});
    }
    setInterval(measureConnection, 120000);

    /* ── Media helpers ── */
    function formatBytes(b) {
        if (!b) return "";
        if (b < 1024)    return b + " B";
        if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
        return (b / 1048576).toFixed(1) + " MB";
    }

    function formatDuration(s) {
        var m = Math.floor(s / 60), sec = Math.round(s % 60);
        return m + ":" + (sec < 10 ? "0" : "") + sec;
    }

    function SpeedTracker() {
        var _s = [], _WIN = 3000;
        return {
            add: function (b) {
                var t = Date.now();
                _s.push({ t: t, b: b });
                while (_s.length > 1 && t - _s[0].t > _WIN) _s.shift();
            },
            mbps: function () {
                if (_s.length < 2) return 0;
                var dt = (_s[_s.length - 1].t - _s[0].t) / 1000;
                return dt > 0.05 ? (_s[_s.length - 1].b - _s[0].b) / dt / 1048576 : 0;
            }
        };
    }

    /* ── Helpers ── */
    function generateId() {
        return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    }

    function escapeHtml(str) {
        return String(str).replace(/[&<>"']/g, function (c) {
            return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c];
        });
    }

    function avatarColorClass(userId) {
        return AVATAR_COLORS[Math.abs(Number(userId) || 0) % AVATAR_COLORS.length];
    }

    function timeStr(timestamp) {
        if (!timestamp) return "";
        const m = String(timestamp).match(/(\d{2}:\d{2})/);
        return m ? m[1] : "";
    }

    function createTransferCard(label, totalBytes, isOwn, partnerId) {
        var article = document.createElement("article");
        article.className = "message-item" + (isOwn ? " message-own" : "");
        article.dataset.messageType = activeChatId === "broadcast" ? "broadcast" : "direct";
        article.dataset.senderId    = isOwn ? String(currentUserId) : String(partnerId || 0);
        article.dataset.receiverId  = isOwn ? String(partnerId || activeChatId) : String(currentUserId);
        article.innerHTML =
            '<div class="message-stack">' +
            '<div class="message-bubble tp-bubble">' +
            '<div class="tp-header">' +
            '<span class="tp-name">' + escapeHtml(label) + '</span>' +
            '<span class="tp-speed"></span>' +
            '</div>' +
            '<div class="tp-bar"><div class="tp-fill"></div></div>' +
            '<div class="tp-stats">Preparing…</div>' +
            '</div></div>';
        list.appendChild(article);
        list.scrollTop = list.scrollHeight;

        var tracker  = SpeedTracker();
        var fillEl   = article.querySelector(".tp-fill");
        var speedEl  = article.querySelector(".tp-speed");
        var statsEl  = article.querySelector(".tp-stats");
        var bubbleEl = article.querySelector(".tp-bubble");

        return {
            update: function (bytes, total) {
                tracker.add(bytes);
                var pct   = total ? Math.round(bytes / total * 100) : 0;
                var speed = tracker.mbps();
                fillEl.style.width  = pct + "%";
                speedEl.textContent = speed > 0 ? speed.toFixed(1) + " MB/s" : "";
                statsEl.textContent = pct + "% \xb7 " + formatBytes(bytes) + " / " + formatBytes(total || 0);
            },
            done: function () {
                article.remove();
            },
            complete: function (fileName, fileSize) {
                if (bubbleEl) {
                    bubbleEl.innerHTML =
                        '<div class="tp-header">' +
                        '<span class="tp-name">' + escapeHtml(fileName || label) + '</span>' +
                        '<span class="tp-done-badge">Sent ✓</span>' +
                        '</div>' +
                        '<div class="tp-stats">' + formatBytes(fileSize || 0) + ' \xb7 transfer complete</div>';
                }
            },
            receiveComplete: function (fileName, fileSize) {
                if (bubbleEl) {
                    bubbleEl.innerHTML =
                        '<div class="tp-header">' +
                        '<span class="tp-name">' + escapeHtml(fileName || label) + '</span>' +
                        '<span class="tp-done-badge">Saved ✓</span>' +
                        '</div>' +
                        '<div class="tp-stats">' + formatBytes(fileSize || 0) + ' \xb7 download complete</div>';
                }
            },
            fail: function (msg) {
                if (bubbleEl) {
                    bubbleEl.className = "message-bubble tp-failed";
                    bubbleEl.innerHTML =
                        '<span class="tp-error">Transfer failed: ' + escapeHtml(msg || "error") + '</span>';
                }
                setTimeout(function () { article.remove(); }, 4000);
            }
        };
    }

    /* ── Media helpers ── */
    function mediaCategory(mime) {
        if (!mime) return "file";
        if (mime.startsWith("image/")) return "image";
        if (mime.startsWith("video/")) return "video";
        if (mime.startsWith("audio/")) return "audio";
        return "file";
    }

    function buildMediaHtml(fr) {
        if (!fr) return "";

        // E2EE file — blob is opaque; client must decrypt before display
        if (fr.is_e2ee) {
            // Voice messages: encrypted audio gets a dedicated playback widget
            if (fr.hint_category === "audio" && typeof VoiceMessageBubble !== "undefined") {
                return VoiceMessageBubble.renderBubble(fr.id, 0);
            }
            var autoDecrypt = fr.hint_category === "image";
            var autoAttr    = autoDecrypt ? ' data-auto-decrypt="1"' : '';
            var fname   = (fr.original_filename && fr.original_filename !== "[encrypted]")
                ? escapeHtml(fr.original_filename) : "Encrypted file";
            var dlLabel = autoDecrypt
                ? '<span class="e2ee-dl-label e2ee-dl-loading">Decrypting…</span>'
                : '<span class="e2ee-dl-label">' + fname + ' \xb7 click to decrypt &amp; open</span>';
            return '<div class="media-wrap media-e2ee">' +
                   '<button class="e2ee-dl-btn" data-file-id="' + String(fr.id) + '"' + autoAttr + '>' +
                   '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">' +
                   '<path d="M18 8h-1V6A5 5 0 0 0 7 6v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12' +
                   'a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2zm-6 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm3-9H9V6' +
                   'a3 3 0 0 1 6 0v2z"/></svg>' +
                   dlLabel +
                   '</button></div>';
        }

        var url    = escapeHtml(fr.url || "/uploads/" + fr.id);
        var name   = escapeHtml(fr.original_filename || "file");
        var sizeHuman = escapeHtml(fr.file_size_human || formatBytes(fr.processed_size || fr.file_size || 0));
        var mime   = fr.mime_type || "";
        var cat    = fr.media_category || mediaCategory(mime);
        var thumb  = fr.thumb_url ? escapeHtml(fr.thumb_url) : null;
        var mediaId = String(fr.id || "");

        // ── Still processing (video transcode) ──────────────────────────────
        if (fr.status === "processing") {
            var poster = thumb
                ? '<img src="' + thumb + '" class="media-poster-blur" alt="">'
                : '<div class="media-poster-placeholder"></div>';
            return '<div class="media-wrap media-processing" data-media-id="' + mediaId + '">' +
                   poster +
                   '<div class="media-spinner-overlay">' +
                   '<div class="spinner" aria-hidden="true"></div>' +
                   '<span>Processing…</span>' +
                   '</div></div>';
        }

        // ── Image — thumbnail-first ──────────────────────────────────────────
        if (cat === "image") {
            var src   = thumb || url;
            var badge = sizeHuman ? '<div class="media-size-badge">' + sizeHuman + '</div>' : "";
            return '<div class="media-wrap media-photo">' +
                   '<a href="' + url + '" target="_blank" rel="noopener" class="media-img-link">' +
                   '<img src="' + src + '" data-full="' + url + '" loading="lazy"' +
                   ' class="media-img' + (thumb ? ' thumb-preview' : '') + '" alt="' + name + '"' +
                   ' onclick="expandPhoto(this);return false;" title="Click to view full size">' +
                   '</a>' +
                   badge + '</div>';
        }

        // ── Video — poster thumbnail, nothing buffered until play ────────────
        if (cat === "video") {
            var posterAttr = thumb ? ' poster="' + thumb + '"' : "";
            var dur = fr.media_duration ? '<div class="media-duration-badge">' + formatDuration(fr.media_duration) + '</div>' : "";
            return '<div class="media-wrap media-video-wrap">' +
                   '<video class="media-video" controls preload="none"' + posterAttr + '>' +
                   '<source src="' + url + '" type="video/mp4">' +
                   '</video>' + dur + '</div>';
        }

        // ── Audio ────────────────────────────────────────────────────────────
        if (cat === "audio") {
            var durSpan = fr.media_duration ? ' <span class="audio-dur">' + formatDuration(fr.media_duration) + '</span>' : "";
            return '<div class="media-wrap media-audio-wrap">' +
                   '<div class="audio-player-row">' +
                   '<audio class="media-audio" controls preload="none">' +
                   '<source src="' + url + '" type="audio/ogg">' +
                   '<source src="' + url + '" type="audio/mpeg">' +
                   '</audio>' + durSpan + '</div></div>';
        }

        // ── Generic file download ─────────────────────────────────────────────
        return '<a class="file-card" href="' + url + '" download="' + name + '">' +
               '<span class="file-card-icon" aria-hidden="true">' +
               '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"' +
               ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
               '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>' +
               '<polyline points="14 2 14 8 20 8"/>' +
               '</svg></span>' +
               '<span class="file-card-info"><strong>' + name + '</strong>' +
               '<small>' + sizeHuman + '</small></span>' +
               '<span class="file-card-dl" aria-hidden="true">' +
               '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"' +
               ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
               '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>' +
               '<polyline points="7 10 12 15 17 10"/>' +
               '<line x1="12" y1="15" x2="12" y2="3"/>' +
               '</svg></span></a>';
    }

    // Expand thumbnail to full image on click
    window.expandPhoto = function (img) {
        var full = img.dataset.full;
        if (!full || img.classList.contains("expanded")) return;
        img.classList.add("expanded");
        img.style.opacity = "0.7";
        var loader = new Image();
        loader.onload = function () {
            img.src = full;
            img.style.opacity = "";
            img.classList.remove("thumb-preview");
        };
        loader.onerror = function () {
            img.classList.remove("expanded");
            img.style.opacity = "";
        };
        loader.src = full;
    };

    function isMobileView() {
        return window.matchMedia("(max-width: 680px)").matches;
    }

    function openMobileChat() {
        if (!isMobileView()) return;
        if (railEl)  railEl.classList.add("mobile-hidden");
        if (panelEl) panelEl.classList.add("mobile-visible");
    }

    function closeMobileChat() {
        if (railEl)  railEl.classList.remove("mobile-hidden");
        if (panelEl) panelEl.classList.remove("mobile-visible");
    }

    function switchTab(name) {
        activeTab = name;
        document.querySelectorAll(".rail-tab").forEach(function (btn) {
            var on = btn.dataset.tab === name;
            btn.classList.toggle("rail-tab-active", on);
            btn.setAttribute("aria-selected", on ? "true" : "false");
        });
        document.querySelectorAll(".tab-panel").forEach(function (panel) {
            var show = panel.id === "tab-panel-" + name;
            panel.hidden = !show;
        });
    }

    function setStatus(text) {
        if (statusEl) {
            statusEl.innerHTML =
                '<span class="pulse-dot" aria-hidden="true"></span>' + escapeHtml(text);
        }
    }

    /* ── Message visibility ── */
    function belongsToChat(el) {
        const type = el.dataset.messageType;
        const sid  = Number(el.dataset.senderId);
        const rid  = Number(el.dataset.receiverId) || null;

        if (activeChatId === "broadcast") return type === "broadcast";
        const cid = Number(activeChatId);
        return (
            type === "direct" &&
            ((sid === currentUserId && rid === cid) ||
             (sid === cid && rid === currentUserId))
        );
    }

    function filterMessages() {
        list.querySelectorAll(".message-item").forEach(function (el) {
            const show = belongsToChat(el);
            el.hidden = !show;
            el.style.display = show ? "" : "none";
        });
        updateEmptyState();
        list.scrollTop = list.scrollHeight;
    }

    function updateEmptyState() {
        if (!emptyChatEl) return;
        const hasVisible = Array.from(list.querySelectorAll(".message-item"))
                                .some(function (el) { return !el.hidden; });
        emptyChatEl.textContent = activeChatId === "broadcast"
            ? "Start the shared room with a message."
            : "No messages in this conversation yet.";
        emptyChatEl.hidden = hasVisible;
        emptyChatEl.style.display = hasVisible ? "none" : "";
    }

    /* ── Conversation previews ── */
    function updatePreview(message) {
        var key = message.message_type === "broadcast" ? "broadcast"
            : String(Number(message.sender_id) === currentUserId
                ? message.receiver_id : message.sender_id);
        var previewEl = document.getElementById("preview-" + key);
        var timeEl    = document.getElementById("preview-time-" + key);
        var content;
        if (message.is_e2ee && message.message_type === "direct") {
            content = "🔒 Encrypted message";
        } else if (message.file_record) {
            content = message.file_record.original_filename || "";
        } else {
            content = String(message.content || "").trim();
        }
        if (previewEl) {
            previewEl.textContent =
                (Number(message.sender_id) === currentUserId ? "You: " : "") +
                content.slice(0, 80);
        }
        if (timeEl) timeEl.textContent = timeStr(message.timestamp);
    }

    function initPreviews() {
        list.querySelectorAll(".message-item").forEach(function (el) {
            var type      = el.dataset.messageType;
            var sid       = Number(el.dataset.senderId);
            var rid       = Number(el.dataset.receiverId) || null;
            var textEl    = el.querySelector(".message-text");
            var msgTimeEl = el.querySelector(".message-time");
            var previewText = textEl
                ? (textEl.textContent || "").trim()
                : (el.dataset.fileName || "");
            if (!previewText) return;
            var key = type === "broadcast" ? "broadcast"
                : String(sid === currentUserId ? rid : sid);
            var previewEl = document.getElementById("preview-" + key);
            var tEl       = document.getElementById("preview-time-" + key);
            if (previewEl) {
                previewEl.textContent =
                    (sid === currentUserId ? "You: " : "") +
                    previewText.slice(0, 80);
            }
            if (tEl && msgTimeEl) tEl.textContent = msgTimeEl.textContent.trim();
        });
    }

    /* ── Live presence helpers ── */
    function setUserOnline(userId, isOnline) {
        var id = String(userId);
        document.querySelectorAll(
            '.conversation-row[data-chat-id="' + id + '"] .status-dot'
        ).forEach(function (dot) {
            dot.classList.toggle("status-dot-offline", !isOnline);
            dot.setAttribute("aria-label", isOnline ? "Online" : "Offline");
        });
    }

    /* Create and wire up a new button for the Chats conversation rail. */
    function _makeConvoBtn(pid, pname, ci) {
        var btn = document.createElement("button");
        btn.className = "conversation-row";
        btn.type = "button";
        btn.setAttribute("role", "option");
        btn.dataset.chatId    = pid;
        btn.dataset.chatName  = pname;
        btn.dataset.chatKind  = "direct";
        btn.dataset.colorIndex = String(ci);
        btn.setAttribute("aria-pressed", "false");
        btn.setAttribute("aria-selected", "false");
        btn.innerHTML =
            '<span class="avatar avatar-sm avatar-c' + ci + '" aria-hidden="true">' +
            escapeHtml(pname.charAt(0).toUpperCase()) + '</span>' +
            '<span class="conversation-copy">' +
            '<span class="conversation-name-row">' +
            '<strong>' + escapeHtml(pname) + '</strong>' +
            '<small class="conversation-time" id="preview-time-' + pid + '"></small>' +
            '</span>' +
            '<small class="conversation-preview" id="preview-' + pid + '"></small>' +
            '</span>' +
            '<span class="status-dot" aria-label="Online"></span>';
        btn.addEventListener("click", function () { setActiveChat(btn); });
        return btn;
    }

    /* Ensure a Chats-panel row exists for the conversation partner in msg. */
    function ensureConvoRow(msg) {
        if (msg.message_type !== "direct") return;
        var isOwn  = Number(msg.sender_id) === currentUserId;
        var pid    = String(isOwn ? msg.receiver_id : msg.sender_id);
        var pname  = isOwn ? (msg.receiver_username || "Unknown") : (msg.sender_username || "Unknown");
        var ci     = Math.abs(Number(pid)) % 8;
        var panel  = document.getElementById("tab-panel-chats");
        if (!panel) return;
        if (panel.querySelector('.conversation-row[data-chat-id="' + pid + '"]')) return;
        var btn      = _makeConvoBtn(pid, pname, ci);
        var convoList = panel.querySelector(".conversation-list");
        if (!convoList) return;
        // Remove "no conversations" placeholder if present
        var placeholder = convoList.querySelector(".empty-state");
        if (placeholder) placeholder.remove();
        // Insert right after the Broadcast row
        var bcast = convoList.querySelector('.conversation-row[data-chat-id="broadcast"]');
        convoList.insertBefore(btn, bcast ? bcast.nextSibling : convoList.firstChild);
    }

    /* Add a newly registered user to the Contacts panel. */
    function addContactRow(payload) {
        var uid   = String(payload.user_id);
        var uname = payload.username  || "Unknown";
        var ci    = Number(payload.color_index || 0) % 8;
        if (payload.public_key) userPubkeys[uid] = payload.public_key;
        var panel = document.getElementById("tab-panel-contacts");
        if (!panel) return;
        if (panel.querySelector('.conversation-row[data-chat-id="' + uid + '"]')) return;
        var btn = document.createElement("button");
        btn.className = "conversation-row contact-row";
        btn.type = "button";
        btn.dataset.chatId    = uid;
        btn.dataset.chatName  = uname;
        btn.dataset.chatKind  = "direct";
        btn.dataset.colorIndex = String(ci);
        btn.setAttribute("aria-pressed", "false");
        btn.setAttribute("aria-selected", "false");
        btn.innerHTML =
            '<span class="avatar avatar-sm avatar-c' + ci + '" aria-hidden="true">' +
            escapeHtml(uname.charAt(0).toUpperCase()) + '</span>' +
            '<span class="conversation-copy">' +
            '<span class="conversation-name-row"><strong>' + escapeHtml(uname) + '</strong></span>' +
            '<small class="conversation-preview">' + escapeHtml(payload.email || "") + '</small>' +
            '</span>' +
            '<span class="status-dot" aria-label="Online"></span>';
        btn.addEventListener("click", function () { setActiveChat(btn); });
        var list = panel.querySelector(".conversation-list");
        if (list) {
            var empty = list.querySelector(".empty-state");
            if (empty) empty.remove();
            list.appendChild(btn);
        }
        // Bump the member-count badge
        var badge = document.querySelector(".rail-header .badge");
        if (badge) {
            var n = parseInt(badge.textContent, 10) || 0;
            badge.textContent = (n + 1) + " members";
        }
    }

    /* ── Switch active conversation ── */
    function setActiveChat(row) {
        activeChatId   = row.dataset.chatId || "broadcast";
        activeChatName = row.dataset.chatName || "Everyone";
        var kind       = row.dataset.chatKind || "broadcast";
        var name       = activeChatName;
        var colorIdx = row.dataset.colorIndex;

        var activeRow = row;
        if (row.closest && row.closest("#tab-panel-contacts")) {
            switchTab("chats");
            var chatsMatch = document.querySelector(
                '#tab-panel-chats .conversation-row[data-chat-id="' + activeChatId + '"]'
            );
            if (chatsMatch) activeRow = chatsMatch;
        }

        // Live query so dynamically-added rows are included
        document.querySelectorAll(".conversation-row[data-chat-id]").forEach(function (r) {
            var active = r === activeRow;
            r.classList.toggle("conversation-active", active);
            r.setAttribute("aria-pressed", active ? "true" : "false");
            r.setAttribute("aria-selected", active ? "true" : "false");
        });

        if (receiverEl) receiverEl.value = activeChatId;
        if (chatTitleEl) {
            if (kind !== "broadcast" && typeof Fingerprint !== "undefined") {
                chatTitleEl.innerHTML = escapeHtml(name) + " " + Fingerprint.inlineBadge(activeChatId);
            } else {
                chatTitleEl.textContent = name;
            }
        }
        if (chatSubtitleEl) {
            chatSubtitleEl.textContent = kind === "broadcast"
                ? "All users · LAN" : "Private · LAN";
        }

        if (chatAvatarEl) {
            if (kind === "broadcast") {
                chatAvatarEl.className = "avatar avatar-broadcast";
                chatAvatarEl.innerHTML =
                    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"' +
                    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
                    '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>' +
                    '<circle cx="9" cy="7" r="4"/>' +
                    '<path d="M23 21v-2a4 4 0 0 0-3-3.87"/>' +
                    '<path d="M16 3.13a4 4 0 0 1 0 7.75"/>' +
                    "</svg>";
            } else {
                var cls = colorIdx !== undefined ? "avatar-c" + colorIdx : avatarColorClass(activeChatId);
                chatAvatarEl.className = "avatar " + cls;
                chatAvatarEl.textContent = name.charAt(0).toUpperCase();
            }
        }

        if (chatContextEl) {
            chatContextEl.textContent = kind === "broadcast"
                ? "Broadcast messages from all users appear here."
                : "Only messages between you and " + name + " appear here.";
        }

        var callBtnEl = document.getElementById("call-btn");
        if (callBtnEl) callBtnEl.style.display = kind === "direct" ? "flex" : "none";

        var vmContainer = document.getElementById("voice-msg-container");
        if (vmContainer) {
            if (kind === "direct") {
                vmContainer.classList.add("vm-visible");
                if (!vmContainer.dataset.mounted) {
                    vmContainer.dataset.mounted = "1";
                    if (typeof VoiceMessageUI !== "undefined") {
                        VoiceMessageUI.mount(vmContainer, function (file, duration) {
                            return _uploadVoiceMsgE2EE(file, duration);
                        });
                    }
                }
            } else {
                vmContainer.classList.remove("vm-visible");
            }
        }

        filterMessages();
        openMobileChat();
        if (!window.matchMedia("(pointer: coarse)").matches && contentEl) contentEl.focus();
    }

    /* ── Build & append a message bubble ── */
    function appendMessage(msg) {
        if (list.querySelector('[data-message-id="' + msg.id + '"]')) return;

        var isOwn      = Number(msg.sender_id) === currentUserId;
        var isBcast    = msg.message_type === "broadcast";
        var senderName = escapeHtml(msg.sender_username || "Unknown");

        if (!isOwn && typeof Notify !== "undefined") {
            var preview = msg.file_record ? "📎 Sent an attachment"
                        : msg.is_e2ee     ? "🔒 Encrypted message"
                        : String(msg.content || "").slice(0, 120);
            Notify.show({
                title:  (msg.sender_username || "Unknown") + (isBcast ? " (broadcast)" : ""),
                body:   preview,
                tag:    "msg-" + (isBcast ? "broadcast" : msg.sender_id),
                chatId: isBcast ? "broadcast" : msg.sender_id,
            });
        }
        var time       = escapeHtml(timeStr(msg.timestamp));
        var colorCls   = avatarColorClass(msg.sender_id);
        var fr         = msg.file_record || null;

        var delBtn = isOwn && !msg.is_deleted
            ? '<button class="msg-del-btn" data-msg-id="' + msg.id + '"' +
              ' title="Delete message" aria-label="Delete message">' +
              '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"' +
              ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
              '<polyline points="3 6 5 6 21 6"/>' +
              '<path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>' +
              '<path d="M10 11v6M14 11v6"/>' +
              '<path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>' +
              '</svg></button>'
            : "";

        var tickSvg = isOwn
            ? '<span class="message-tick" aria-label="Sent">' +
              '<svg width="16" height="10" viewBox="0 0 16 10" fill="none" aria-hidden="true">' +
              '<path d="M1 5.5L4.5 9L11 1" stroke="currentColor" stroke-width="1.6"' +
              ' stroke-linecap="round" stroke-linejoin="round"/>' +
              '<path d="M6 9L12.5 1" stroke="currentColor" stroke-width="1.6"' +
              ' stroke-linecap="round" stroke-linejoin="round"/>' +
              '</svg></span>'
            : "";

        var e2eeBadge = (msg.is_e2ee && msg.message_type === "direct")
            ? '<span class="e2ee-badge" title="End-to-end encrypted" aria-label="End-to-end encrypted">' +
              '<svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">' +
              '<path d="M18 8h-1V6A5 5 0 0 0 7 6v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10' +
              'a2 2 0 0 0-2-2zm-6 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm3-9H9V6a3 3 0 0 1 6 0v2z"/>' +
              '</svg></span>'
            : "";

        var senderNameHtml = (!isOwn && isBcast)
            ? '<div class="message-sender-name">' + senderName + '</div>' : "";

        var avatarHtml = !isOwn
            ? '<span class="avatar avatar-thread ' + colorCls + '" aria-hidden="true">' +
              escapeHtml((msg.sender_username || "U").charAt(0).toUpperCase()) +
              '</span>'
            : "";

        var isE2EE   = msg.is_e2ee && msg.message_type === "direct" && !msg.is_deleted && !fr;
        var bodyHtml;
        if (msg.is_deleted) {
            bodyHtml = '<p class="message-deleted">Message deleted</p>';
        } else if (fr) {
            bodyHtml = buildMediaHtml(fr);
        } else if (isE2EE) {
            // Sender reads their own copy; recipient reads the recipient copy.
            var ct = isOwn ? (msg.sender_copy || "")        : (msg.content       || "");
            var ep = isOwn ? (msg.sender_ephemeral_pub || "") : (msg.ephemeral_pub || "");
            var iv = isOwn ? (msg.sender_iv || "")           : (msg.iv            || "");
            bodyHtml = '<p class="message-text e2ee-pending"' +
                ' data-ct="' + escapeHtml(ct) + '"' +
                ' data-ep="' + escapeHtml(ep) + '"' +
                ' data-iv="' + escapeHtml(iv) + '">' +
                '<span class="e2ee-lock-icon" aria-hidden="true"></span>' +
                'Decrypting…</p>';
        } else {
            bodyHtml = '<p class="message-text">' + escapeHtml(msg.content || "") + '</p>';
        }

        var html =
            avatarHtml +
            '<div class="message-stack">' +
            senderNameHtml +
            '<div class="message-bubble' + (fr && !msg.is_deleted ? ' media-bubble' : '') + '">' +
            bodyHtml +
            '<div class="message-time-row">' +
            delBtn +
            e2eeBadge +
            '<span class="message-time">' + time + '</span>' +
            tickSvg +
            '</div>' +
            '</div>' +
            '</div>';

        var article = document.createElement("article");
        article.className = "message-item" + (isOwn ? " message-own" : "");
        article.dataset.messageId   = msg.id;
        article.dataset.messageType = msg.message_type || "";
        article.dataset.senderId    = String(msg.sender_id || "");
        article.dataset.receiverId  = String(msg.receiver_id || "");
        if (fr) article.dataset.fileName = fr.original_filename || "";
        article.innerHTML = html;

        var shouldShow = belongsToChat(article);
        article.hidden = !shouldShow;
        article.style.display = shouldShow ? "" : "none";

        if (emptyChatEl && shouldShow) {
            emptyChatEl.hidden = true;
            emptyChatEl.style.display = "none";
        }

        list.appendChild(article);
        if (shouldShow) list.scrollTop = list.scrollHeight;
        updateEmptyState();
        ensureConvoRow(msg);
        updatePreview(msg);
        setStatus("Connected");

        // Auto-decrypt images / small E2EE files immediately after appending
        var autoBtn = article.querySelector('.e2ee-dl-btn[data-auto-decrypt="1"]');
        if (autoBtn) decryptAndRender(autoBtn);

        // Async decrypt E2EE messages after appending
        if (isE2EE) {
            var _ct = isOwn ? (msg.sender_copy || "")         : (msg.content       || "");
            var _ep = isOwn ? (msg.sender_ephemeral_pub || "") : (msg.ephemeral_pub || "");
            var _iv = isOwn ? (msg.sender_iv || "")            : (msg.iv            || "");
            E2EE.decrypt(_ep, _iv, _ct).then(function (plain) {
                var pending = article.querySelector(".e2ee-pending");
                if (!pending) return;
                if (plain !== null) {
                    pending.className  = "message-text";
                    pending.innerHTML  = escapeHtml(plain);
                } else {
                    pending.className  = "message-text e2ee-fail";
                    pending.innerHTML  = E2EE.isCryptoAvailable()
                        ? '<em>Unable to decrypt message</em>'
                        : '<em>Encrypted — open via <strong>https://</strong> to decrypt</em>';
                }
                if (shouldShow) list.scrollTop = list.scrollHeight;
            });
        }
    }

    /* ── Protocol: dispatch incoming typed envelope ── */
    function dispatch(envelope) {
        var type    = envelope.type    || "";
        var payload = envelope.payload || {};
        var code    = envelope.code    || "";
        var msg     = envelope.message || "An error occurred.";

        if (type === "new_message") {
            appendMessage(payload);
        } else if (type === "media_ready") {
            var mediaId = String(payload.media_id || "");
            var wrap = list.querySelector('[data-media-id="' + mediaId + '"]');
            if (wrap) {
                var fr = {
                    id: payload.media_id,
                    mime_type: payload.mime_type || "video/mp4",
                    status: "ready",
                    url: payload.url,
                    thumb_url: payload.thumb_url || null,
                    media_duration: payload.duration || null,
                    media_category: "video",
                };
                var bubble = wrap.closest(".message-bubble");
                if (bubble) {
                    // Replace only the media-wrap inside the bubble
                    var timeRow = bubble.querySelector(".message-time-row");
                    bubble.innerHTML = buildMediaHtml(fr);
                    if (timeRow) bubble.appendChild(timeRow);
                }
            }
            setStatus("Connected");
        } else if (type === "message_deleted") {
            var delId = String(payload.message_id || "");
            var delEl = list.querySelector('[data-message-id="' + delId + '"]');
            if (delEl) {
                var bubble = delEl.querySelector(".message-bubble");
                if (bubble) {
                    bubble.className = "message-bubble";
                    var timeRow = bubble.querySelector(".message-time-row");
                    bubble.innerHTML = '<p class="message-deleted">Message deleted</p>';
                    if (timeRow) {
                        timeRow.querySelector && timeRow.querySelectorAll(".msg-del-btn")
                            .forEach(function (b) { b.remove(); });
                        bubble.appendChild(timeRow);
                    }
                }
            }
        } else if (type === "media_failed") {
            var failId = String(payload.media_id || "");
            var failWrap = list.querySelector('[data-media-id="' + failId + '"]');
            if (failWrap) {
                failWrap.innerHTML =
                    '<div class="media-error"><span>&#9888; Media unavailable</span></div>';
            }
        } else if (type === "user_online") {
            onlineUsers.add(Number(payload.user_id));
            setUserOnline(payload.user_id, true);
        } else if (type === "user_offline") {
            onlineUsers.delete(Number(payload.user_id));
            setUserOnline(payload.user_id, false);
        } else if (type === "online_users") {
            // Bulk presence snapshot sent on connect
            onlineUsers = new Set((payload.user_ids || []).map(Number));
            var onlineSet = {};
            (payload.user_ids || []).forEach(function (id) { onlineSet[String(id)] = true; });
            document.querySelectorAll(".conversation-row[data-chat-id] .status-dot").forEach(function (dot) {
                var chatId = dot.closest(".conversation-row").dataset.chatId;
                if (chatId === "broadcast") return;
                var isOn = !!onlineSet[chatId];
                dot.classList.toggle("status-dot-offline", !isOn);
                dot.setAttribute("aria-label", isOn ? "Online" : "Offline");
            });
        } else if (type === "p2p_offer") {
            if (typeof P2PTransfer !== "undefined" && E2EE.getPrivateKey()) {
                _p2pSenders.set(payload.transfer_id, {
                    id: payload.sender_id, name: payload.sender_name || "Someone"
                });
                P2PTransfer.handleOffer(payload, E2EE.getPrivateKey()).catch(function (e) {
                    console.error("[P2P] handleOffer error", e);
                });
                if (typeof Notify !== "undefined") Notify.show({
                    title:  (payload.sender_name || "Someone") + " wants to send you a file",
                    body:   (payload.file_name || "file") + " · " + formatBytes(payload.file_size || 0),
                    tag:    "p2p-" + payload.transfer_id,
                    chatId: payload.sender_id,
                });
            }
        } else if (type === "p2p_answer") {
            if (typeof P2PTransfer !== "undefined")
                P2PTransfer.handleAnswer(payload).catch(function (e) {
                    console.error("[P2P] handleAnswer error", e);
                });
        } else if (type === "p2p_ice") {
            if (typeof P2PTransfer !== "undefined")
                P2PTransfer.handleIce(payload).catch(function (e) {
                    console.warn("[P2P] handleIce error", e);
                });
        } else if (type === "p2p_decline") {
            var decCard = _p2pCards.get(payload.transfer_id);
            if (decCard) {
                decCard.fail("Recipient declined the transfer");
                _p2pCards.delete(payload.transfer_id);
            }
            setStatus("File transfer was declined.");
            if (typeof Notify !== "undefined") Notify.show({
                title: "File transfer declined",
                body:  "The recipient declined your file.",
                tag:   "p2p-" + payload.transfer_id,
            });
        } else if (type === "call_invite") {
            if (typeof VoiceChat !== "undefined") VoiceChat.handleInvite(payload);
            if (typeof Notify !== "undefined") Notify.show({
                title:  "📞 Incoming voice call",
                body:   (payload.caller_name || "Someone") + " is calling you",
                tag:    "call-" + payload.call_id,
                chatId: payload.caller_id,
            });
        } else if (type === "call_accept") {
            if (typeof VoiceChat !== "undefined") VoiceChat.handleAccept(payload);
        } else if (type === "call_decline") {
            if (typeof VoiceChat !== "undefined") VoiceChat.handleDecline(payload);
        } else if (type === "call_ice") {
            if (typeof VoiceChat !== "undefined") VoiceChat.handleIce(payload);
        } else if (type === "call_end") {
            if (typeof VoiceChat !== "undefined") VoiceChat.handleEnd();
        } else if (type === "user_joined") {
            addContactRow(payload);
            setUserOnline(payload.user_id, true);
            if (typeof Notify !== "undefined") Notify.show({
                title:  "New user joined",
                body:   (payload.username || "Someone") + " joined IntraComms",
                tag:    "joined-" + payload.user_id,
                chatId: payload.user_id,
            });
        } else if (type === "client_config") {
            UPLOAD_CONFIG = payload || UPLOAD_CONFIG;
            connectionTier = payload.tier || connectionTier;
        } else if (type === "error") {
            setStatus(code === "RATE_LIMITED"
                ? "Sending too fast — please slow down."
                : "Error: " + msg);
        }
    }

    /* ── Send a typed envelope over the socket (plaintext path) ── */
    function sendWs(receiverId, content, requestId) {
        socket.send("42" + JSON.stringify([
            "message",
            {
                type:      "send_message",
                payload:   { receiver_id: receiverId, content: content },
                requestId: requestId,
            }
        ]));
    }

    /* ── Encrypt and send over WebSocket ─────────────────────────────────────
     * Encrypts TWICE: once for the recipient (so they can read it), and once
     * for the sender's own public key (so the sender can read their own sent
     * messages). Both ciphertexts are stored by the server; each side decrypts
     * only the copy addressed to them.
     * ─────────────────────────────────────────────────────────────────────── */
    function _sendEncrypted(receiverId, content, requestId, recipientPub) {
        if (recipientPub && E2EE.isReady()) {
            var myPub = E2EE.getMyPubKey();
            Promise.all([
                E2EE.encryptFor(recipientPub, content),
                myPub ? E2EE.encryptFor(myPub, content) : Promise.resolve(null),
            ]).then(function (results) {
                var forRecipient = results[0];
                var forSelf      = results[1];
                socket.send("42" + JSON.stringify([
                    "message",
                    {
                        type: "send_message",
                        payload: {
                            receiver_id:          receiverId,
                            content:              forRecipient.ciphertext,
                            ephemeral_pub:        forRecipient.ephemeral_pub,
                            iv:                   forRecipient.iv,
                            sender_copy:          forSelf ? forSelf.ciphertext    : "",
                            sender_ephemeral_pub: forSelf ? forSelf.ephemeral_pub : "",
                            sender_iv:            forSelf ? forSelf.iv            : "",
                            is_e2ee:              true,
                        },
                        requestId: requestId,
                    }
                ]));
            }).catch(function () {
                sendWs(receiverId, content, requestId);
            });
        } else {
            sendWs(receiverId, content, requestId);
        }
    }

    /* ── Send with E2EE when possible ───────────────────────────────────────
     * DM + recipient has a registered public key + E2EE is initialised
     *   → encrypt client-side, send ciphertext
     * Broadcast / no pubkey / E2EE unavailable
     *   → send plaintext (broadcast is public by nature)
     *
     * If the recipient pubkey isn't cached (e.g. they registered after this
     * page loaded), fetch it live from the server before encrypting.
     * ─────────────────────────────────────────────────────────────────────── */
    function sendMessage(receiverId, content, requestId) {
        if (receiverId === "broadcast") {
            sendWs(receiverId, content, requestId);
            return;
        }

        var recipientPub = userPubkeys[String(receiverId)] || null;

        if (recipientPub) {
            _sendEncrypted(receiverId, content, requestId, recipientPub);
        } else {
            // Pubkey not yet cached — fetch live, then encrypt
            fetch("/api/users/" + receiverId + "/pubkey")
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.public_key) {
                        userPubkeys[String(receiverId)] = data.public_key;
                        if (typeof Fingerprint !== "undefined") Fingerprint.recordSeen(receiverId, data.public_key);
                    }
                    _sendEncrypted(receiverId, content, requestId, data.public_key || null);
                })
                .catch(function () {
                    sendWs(receiverId, content, requestId);
                });
        }
    }

    /* ── Flush buffered messages after reconnect ── */
    function flushQueue() {
        while (messageQueue.length > 0) {
            var item = messageQueue.shift();
            sendMessage(item.receiverId, item.content, item.requestId);
        }
    }

    /* ── WebSocket: raw EIO4 packet handler ── */
    function handlePacket(raw) {
        if (raw === "2") { socket.send("3"); return; }             // ping → pong
        if (raw.charAt(0) === "0") { socket.send("40"); return; }  // EIO open → connect

        if (raw.indexOf("40") === 0) {                             // Socket.IO connected
            connected = true;
            reconnectDelay = 1000;   // reset backoff on success
            setStatus("Connected");
            flushQueue();            // deliver any queued messages
            measureConnection();     // report RTT + tier to server
            return;
        }

        if (raw.indexOf("42") === 0) {
            try {
                var parts = JSON.parse(raw.slice(2));
                if (parts[0] === "message") dispatch(parts[1] || {});
            } catch (_) {}
        }
    }

    /* ── Connect with exponential backoff ── */
    function connectSocket() {
        var proto = window.location.protocol === "https:" ? "wss:" : "ws:";
        var url   = proto + "//" + window.location.host + "/socket.io/?EIO=4&transport=websocket";
        socket = new WebSocket(url);

        socket.addEventListener("message", function (e) { handlePacket(String(e.data)); });

        socket.addEventListener("close", function () {
            connected = false;
            var secs = Math.round(reconnectDelay / 1000);
            setStatus("Disconnected — reconnecting in " + secs + "s…");
            window.setTimeout(function () {
                reconnectDelay = Math.min(reconnectDelay * 2, MAX_DELAY);
                connectSocket();
            }, reconnectDelay);
        });

        socket.addEventListener("error", function () {
            connected = false;
            setStatus("Connection unavailable");
        });
    }

    /* ── Form submit ── */
    form.addEventListener("submit", function (e) {
        var content    = contentEl ? contentEl.value.trim() : "";
        var receiverId = receiverEl ? receiverEl.value : "broadcast";
        if (!content) { e.preventDefault(); return; }

        if (connected && socket && socket.readyState === WebSocket.OPEN) {
            // Primary path: send via WebSocket with structured envelope
            e.preventDefault();
            sendMessage(receiverId, content, generateId());
            contentEl.value = "";
            resizeTextarea();
            updateCharCount();
            animateSend();
            setStatus("Sending…");
        } else if (socket) {
            // Socket exists but reconnecting — buffer for delivery after reconnect
            e.preventDefault();
            messageQueue.push({ receiverId: receiverId, content: content, requestId: generateId() });
            setStatus("Queued — will send when reconnected");
            contentEl.value = "";
            resizeTextarea();
            updateCharCount();
        } else {
            // No WebSocket — block send entirely; plaintext HTTP is not allowed
            e.preventDefault();
            setStatus("Cannot send: encrypted channel unavailable. Reload the page.");
        }
    });

    /* ── Textarea auto-resize ── */
    function resizeTextarea() {
        if (!contentEl) return;
        contentEl.style.height = "auto";
        contentEl.style.height = Math.min(contentEl.scrollHeight, 130) + "px";
    }

    function updateCharCount() {
        if (charCountEl && contentEl) {
            charCountEl.textContent = contentEl.value.length + " / 2000";
        }
    }

    function animateSend() {
        if (!sendBtn) return;
        sendBtn.classList.remove("is-sending");
        window.requestAnimationFrame(function () { sendBtn.classList.add("is-sending"); });
    }

    if (contentEl) {
        contentEl.addEventListener("input", function () {
            resizeTextarea();
            updateCharCount();
        });
        contentEl.addEventListener("keydown", function (e) {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                form.requestSubmit ? form.requestSubmit() : form.submit();
            }
        });
        resizeTextarea();
        updateCharCount();
    }

    /* ── Search ── */
    function makeSearchFilter(inputEl, panelEl) {
        if (!inputEl || !panelEl) return;
        inputEl.addEventListener("input", function () {
            var q = inputEl.value.trim().toLowerCase();
            panelEl.querySelectorAll(".conversation-row").forEach(function (row) {
                var show = !q || row.textContent.toLowerCase().includes(q);
                row.hidden = !show;
                row.style.display = show ? "" : "none";
            });
        });
    }

    makeSearchFilter(chatSearchEl,    document.getElementById("tab-panel-chats"));
    makeSearchFilter(contactSearchEl, document.getElementById("tab-panel-contacts"));

    /* ── Tab buttons ── */
    document.querySelectorAll(".rail-tab").forEach(function (btn) {
        btn.addEventListener("click", function () { switchTab(btn.dataset.tab); });
    });

    /* ── Back button (mobile) ── */
    if (backBtn) {
        backBtn.addEventListener("click", closeMobileChat);
    }

    // P2P transfer state — tracks in-progress sender cards and sender identities
    var _p2pCards   = new Map(); // transferId → card
    var _p2pSenders = new Map(); // transferId → {id, name}

    function _sendP2PEvent(event, data) {
        if (!socket || socket.readyState !== WebSocket.OPEN) return;
        socket.send("42" + JSON.stringify([event, data]));
    }

    function uploadFile(file) {
        var P2P_MIN    = 50 * 1024 * 1024;   // files > 50 MB go P2P
        var STORE_MAX  = 50 * 1024 * 1024;   // server upload ceiling
        var receiverId = receiverEl ? receiverEl.value : "broadcast";

        // Large files in direct messages → P2P (server cannot store these)
        if (file.size > P2P_MIN && receiverId !== "broadcast"
                && typeof P2PTransfer !== "undefined") {
            _uploadFileP2P(file, receiverId);
            return;
        }

        if (file.size > STORE_MAX) {
            setStatus("File too large (max 50 MB). Large files can only be sent in direct messages via P2P.");
            return;
        }

        // Videos go via the chunked route (server needs plaintext for ffmpeg)
        if (file.type.startsWith("video/")) { uploadVideoChunks(file); return; }

        // Non-video direct messages: encrypt client-side before upload
        if (receiverId !== "broadcast" && E2EE.isReady()) {
            var cached = userPubkeys[String(receiverId)];
            if (cached) {
                _uploadFileE2EE(file, receiverId, cached);
            } else {
                fetch("/api/users/" + receiverId + "/pubkey")
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        if (data.public_key) {
                            userPubkeys[String(receiverId)] = data.public_key;
                            if (typeof Fingerprint !== "undefined") Fingerprint.recordSeen(receiverId, data.public_key);
                            _uploadFileE2EE(file, receiverId, data.public_key);
                        } else {
                            _uploadFilePlain(file, receiverId);
                        }
                    })
                    .catch(function () { _uploadFilePlain(file, receiverId); });
            }
            return;
        }

        _uploadFilePlain(file, receiverId);
    }

    function _uploadFileP2P(file, receiverId) {
        var label = file.name.length > 28 ? file.name.slice(0, 26) + "…" : file.name;

        function doP2P(recipientPub) {
            if (!recipientPub) {
                setStatus("Recipient has no encryption key — cannot start P2P transfer.");
                return;
            }
            if (!E2EE.getPrivateKey()) {
                setStatus("Encryption not ready — please wait a moment and try again.");
                return;
            }
            var card = createTransferCard(label, file.size, true, receiverId);
            setStatus("Connecting P2P to " + activeChatName + "…");

            P2PTransfer.sendFile(file, Number(receiverId), recipientPub)
                .then(function (transferId) {
                    _p2pCards.set(transferId, card);
                    P2PTransfer.onProgress(transferId, function (sent, total) {
                        card.update(sent, total);
                        setStatus("P2P → " + label + " \xb7 " + (total ? Math.round(sent / total * 100) : 0) + "%");
                    });
                    P2PTransfer.onComplete(transferId, function (name, size) {
                        card.complete(name, size);
                        _p2pCards.delete(transferId);
                        setStatus("Connected");
                        if (typeof Notify !== "undefined") Notify.show({
                            title: "File sent ✓",
                            body:  name + " · " + formatBytes(size) + " delivered",
                            tag:   "p2p-" + transferId,
                        });
                    });
                })
                .catch(function (err) {
                    card.fail(err.message || "P2P setup failed");
                    setStatus("P2P transfer failed: " + (err.message || "error"));
                });
        }

        var cached = userPubkeys[String(receiverId)];
        if (cached) {
            doP2P(cached);
        } else {
            fetch("/api/users/" + receiverId + "/pubkey")
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.public_key) userPubkeys[String(receiverId)] = data.public_key;
                    doP2P(data.public_key || null);
                })
                .catch(function () { setStatus("Cannot fetch recipient key for P2P."); });
        }
    }

    function _showP2PIncoming(transferId, meta) {
        var senderInfo = _p2pSenders.get(transferId) || {};
        var senderName = senderInfo.name || "Someone";
        var sizeStr    = formatBytes(meta.size || 0);
        var fname      = escapeHtml(meta.name || "file");

        var overlay = document.createElement("div");
        overlay.className = "p2p-incoming-overlay";
        overlay.innerHTML =
            '<div class="p2p-incoming-modal">' +
            '<div class="p2p-incoming-title">' + escapeHtml(senderName) + ' wants to send you a file</div>' +
            '<div class="p2p-incoming-meta">' +
            '<span class="p2p-fname">' + fname + '</span>' +
            '<span class="p2p-fsize">' + sizeStr + '</span>' +
            '</div>' +
            '<div class="tp-bar p2p-recv-bar" hidden><div class="tp-fill"></div></div>' +
            '<div class="p2p-recv-stats" hidden></div>' +
            '<div class="p2p-incoming-actions">' +
            '<button class="p2p-decline-btn" type="button">Decline</button>' +
            '<button class="p2p-accept-btn" type="button">Accept</button>' +
            '</div>' +
            '</div>';
        document.body.appendChild(overlay);

        var fillEl   = overlay.querySelector(".tp-fill");
        var barEl    = overlay.querySelector(".p2p-recv-bar");
        var statsEl  = overlay.querySelector(".p2p-recv-stats");
        var titleEl  = overlay.querySelector(".p2p-incoming-title");
        var actionsEl = overlay.querySelector(".p2p-incoming-actions");

        overlay.querySelector(".p2p-accept-btn").addEventListener("click", function () {
            this.disabled = true;
            overlay.querySelector(".p2p-decline-btn").disabled = true;
            titleEl.textContent = "Receiving — do not close this tab";
            barEl.hidden  = false;
            statsEl.hidden = false;
            statsEl.textContent = "Starting…";

            P2PTransfer.onProgress(transferId, function (recv, total) {
                var pct = total ? Math.round(recv / total * 100) : 0;
                fillEl.style.width   = pct + "%";
                statsEl.textContent  = pct + "% \xb7 " + formatBytes(recv) + " / " + formatBytes(total);
            });
            P2PTransfer.onComplete(transferId, function (name, size, elapsed) {
                titleEl.textContent  = "Saved ✓";
                statsEl.textContent  = formatBytes(size) + " \xb7 done in " + elapsed.toFixed(1) + "s";
                actionsEl.hidden     = true;
                _p2pSenders.delete(transferId);
                setTimeout(function () { overlay.remove(); }, 3000);
                if (typeof Notify !== "undefined") Notify.show({
                    title: "File received ✓",
                    body:  name + " · " + formatBytes(size) + " saved to Downloads",
                    tag:   "p2p-" + transferId,
                });
            });

            P2PTransfer.accept(transferId);
        });

        overlay.querySelector(".p2p-decline-btn").addEventListener("click", function () {
            P2PTransfer.decline(transferId);
            _p2pSenders.delete(transferId);
            overlay.remove();
        });
    }

    /* Resize + re-encode an image to WebP using canvas before encryption.
       Respects the tier-adaptive photo_max_dim and photo_quality from UPLOAD_CONFIG.
       Returns a Promise<File>; resolves to the original file if canvas is unavailable
       or the MIME type is not a compressible image. */
    function _compressImage(file) {
        var compressible = ["image/jpeg", "image/png", "image/webp", "image/gif"];
        if (!file.type.startsWith("image/") || compressible.indexOf(file.type) === -1) {
            return Promise.resolve(file);
        }
        if (!window.createImageBitmap || !document.createElement) {
            return Promise.resolve(file);
        }

        var maxDim  = (UPLOAD_CONFIG && UPLOAD_CONFIG.photo_max_dim)  || 1920;
        // photo_quality from server is 0-100; canvas quality is 0.0-1.0
        var quality = (UPLOAD_CONFIG && UPLOAD_CONFIG.photo_quality != null)
                      ? UPLOAD_CONFIG.photo_quality / 100
                      : 0.85;

        return createImageBitmap(file).then(function (bmp) {
            var w = bmp.width, h = bmp.height;
            if (w > maxDim || h > maxDim) {
                var scale = maxDim / Math.max(w, h);
                w = Math.round(w * scale);
                h = Math.round(h * scale);
            }
            var canvas = document.createElement("canvas");
            canvas.width  = w;
            canvas.height = h;
            canvas.getContext("2d").drawImage(bmp, 0, 0, w, h);
            bmp.close();

            return new Promise(function (resolve) {
                canvas.toBlob(function (blob) {
                    if (!blob) { resolve(file); return; }
                    // Preserve the original name but signal it is now WebP
                    var newName = file.name.replace(/\.[^.]+$/, "") + ".webp";
                    resolve(new File([blob], newName, { type: "image/webp" }));
                }, "image/webp", quality);
            });
        }).catch(function () {
            return file; // fall back to uncompressed on any error
        });
    }

    function _uploadFileE2EE(file, receiverId, recipientPub) {
        var label = file.name.length > 24 ? file.name.slice(0, 22) + "…" : file.name;
        var myPub = E2EE.getMyPubKey();
        var card  = null;

        var prepareFile = file.type.startsWith("image/")
            ? (setStatus("Compressing " + label + "…"), _compressImage(file))
            : Promise.resolve(file);

        prepareFile.then(function (ready) {
            setStatus("Encrypting " + label + "…");
            card = createTransferCard(label, ready.size, true, receiverId);
            return FileE2EE.uploadEncryptedFile(ready, receiverId, recipientPub, myPub, function (loaded, total) {
                card.update(loaded, total);
            });
        }).then(function () {
            if (card) card.done();
            setStatus("Connected");
        }).catch(function (err) {
            if (card) card.fail(err.message || "error");
            setStatus("Encrypted upload failed: " + (err.message || "error"));
        });
    }

    function _uploadVoiceMsgE2EE(file, durationSeconds) {
        var receiverId = receiverEl ? receiverEl.value : null;
        if (!receiverId || receiverId === "broadcast") return Promise.reject(new Error("No DM recipient"));
        var recipientPub = userPubkeys[String(receiverId)];
        var myPub = E2EE.getMyPubKey();
        var label = "voice message";

        function doUpload(pub) {
            if (!pub) return Promise.reject(new Error("Recipient has no encryption key"));
            setStatus("Encrypting voice message…");
            return FileE2EE.uploadEncryptedFile(
                file, receiverId, pub, myPub,
                function (loaded, total) { setStatus("Sending voice message \xb7 " + (total ? Math.round(loaded / total * 100) : 0) + "%"); },
                { duration: durationSeconds }
            ).then(function () { setStatus("Connected"); });
        }

        if (recipientPub) return doUpload(recipientPub);
        return fetch("/api/users/" + receiverId + "/pubkey")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.public_key) userPubkeys[String(receiverId)] = data.public_key;
                return doUpload(data.public_key || null);
            });
    }

    function _uploadFilePlain(file, receiverId) {
        var label    = file.name.length > 24 ? file.name.slice(0, 22) + "…" : file.name;
        var formData = new FormData();
        formData.append("file", file);
        formData.append("receiver_id", receiverId);
        var card = createTransferCard(label, file.size, true, receiverId);
        var xhr = new XMLHttpRequest();
        xhr.upload.addEventListener("progress", function (e) {
            if (e.lengthComputable) {
                card.update(e.loaded, e.total);
                setStatus("Uploading " + label + " \xb7 " + Math.round(e.loaded / e.total * 100) + "%");
            }
        });
        xhr.addEventListener("load", function () {
            if (xhr.status >= 200 && xhr.status < 300) {
                card.done();
                setStatus("Connected");
            } else {
                var msg = "Upload failed";
                try { msg = JSON.parse(xhr.responseText).error || msg; } catch (_) {}
                card.fail(msg);
                setStatus(msg);
            }
        });
        xhr.addEventListener("error", function () {
            card.fail("network error");
            setStatus("Upload failed (network error)");
        });
        xhr.open("POST", "/upload");
        xhr.send(formData);
    }

    /* ── Chunked video upload with exponential-backoff retry ── */
    function uploadVideoChunks(file) {
        var CHUNK_SIZE  = (UPLOAD_CONFIG && UPLOAD_CONFIG.video_chunk_size) || (5 * 1024 * 1024);
        var totalChunks = Math.ceil(file.size / CHUNK_SIZE);
        var mediaId     = generateId();
        var receiverId  = receiverEl ? receiverEl.value : "broadcast";
        var MAX_RETRY   = 4;
        var label       = file.name.length > 28 ? file.name.slice(0, 26) + "…" : file.name;

        setStatus("Uploading " + label + " · 0%");

        function sendChunk(idx) {
            if (idx >= totalChunks) {
                setStatus("Processing…");
                return;
            }
            var attempt = 0;
            var delay   = 1000;

            function tryChunk() {
                var start = idx * CHUNK_SIZE;
                var chunk = file.slice(start, start + CHUNK_SIZE);
                var form  = new FormData();
                form.append("media_id",     mediaId);
                form.append("chunk_index",  idx);
                form.append("total_chunks", totalChunks);
                form.append("receiver_id",  receiverId);
                form.append("chunk",        chunk, file.name);
                if (idx === 0) form.append("filename", file.name);

                var xhr = new XMLHttpRequest();
                xhr.addEventListener("load", function () {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        var pct = Math.round(((idx + 1) / totalChunks) * 100);
                        setStatus("Uploading " + label + " · " + pct + "%");
                        sendChunk(idx + 1);
                    } else {
                        retry();
                    }
                });
                xhr.addEventListener("error", retry);
                xhr.open("POST", "/upload/video/chunk");
                xhr.send(form);
            }

            function retry() {
                attempt++;
                if (attempt >= MAX_RETRY) {
                    setStatus("Upload failed after " + MAX_RETRY + " retries");
                    return;
                }
                window.setTimeout(function () {
                    delay = Math.min(delay * 2, 16000);
                    tryChunk();
                }, delay);
            }

            tryChunk();
        }

        sendChunk(0);
    }

    if (attachBtn && fileInputEl) {
        attachBtn.addEventListener("click", function () { fileInputEl.click(); });
        fileInputEl.addEventListener("change", function () {
            var file = fileInputEl.files[0];
            if (file) { uploadFile(file); }
            fileInputEl.value = "";
        });
    }

    /* ── Shared: decrypt an E2EE file button and replace it with the media ── */
    function decryptAndRender(btn) {
        if (!btn || btn.disabled) return;
        var fileId = btn.dataset.fileId;
        if (!fileId) return;
        btn.disabled = true;
        var label = btn.querySelector(".e2ee-dl-label");
        if (label) label.textContent = "Decrypting…";

        FileE2EE.downloadAndDecrypt(Number(fileId), function (url, filename, mimeType) {
            var cat  = mimeType.startsWith("image/") ? "image"
                     : mimeType.startsWith("audio/") ? "audio"
                     : mimeType.startsWith("video/") ? "video" : "file";
            var wrap = btn.parentNode;
            if (!wrap) return;

            if (cat === "image") {
                var img = document.createElement("img");
                img.src = url;
                img.className = "media-img";
                img.alt = filename;
                img.style.maxWidth = "280px";
                img.style.borderRadius = "8px";
                wrap.replaceChild(img, btn);
            } else if (cat === "audio") {
                var audio = document.createElement("audio");
                audio.controls = true;
                audio.preload = "none";
                var src = document.createElement("source");
                src.src = url;
                src.type = mimeType;
                audio.appendChild(src);
                wrap.replaceChild(audio, btn);
            } else if (cat === "video") {
                var video = document.createElement("video");
                video.controls = true;
                video.preload = "none";
                video.className = "media-video";
                var vsrc = document.createElement("source");
                vsrc.src = url;
                vsrc.type = mimeType;
                video.appendChild(vsrc);
                wrap.replaceChild(video, btn);
            } else {
                var a = document.createElement("a");
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                btn.disabled = false;
                if (label) label.textContent = "Encrypted file \xb7 click to decrypt & open";
            }
        }).catch(function (err) {
            btn.disabled = false;
            if (label) label.textContent = "Decryption failed — " + (err.message || "try again");
        });
    }

    /* ── E2EE file: decrypt on click (large files only) ── */
    list.addEventListener("click", function (e) {
        var btn = e.target.closest(".e2ee-dl-btn");
        if (!btn || btn.dataset.autoDecrypt) return; // auto-decrypt buttons handled separately
        decryptAndRender(btn);
    });

    /* ── Message delete ── */
    list.addEventListener("click", function (e) {
        var btn = e.target.closest(".msg-del-btn");
        if (!btn) return;
        var msgId = btn.dataset.msgId;
        if (!msgId) return;
        btn.disabled = true;
        fetch("/messages/" + msgId + "/delete", { method: "POST" })
            .then(function (r) {
                if (!r.ok) { btn.disabled = false; }
            })
            .catch(function () { btn.disabled = false; });
    });

    /* ── Sidebar click ── */
    convRows.forEach(function (row) {
        row.addEventListener("click", function () { setActiveChat(row); });
    });

    /* ── Decrypt E2EE messages that were server-rendered as ciphertext ── */
    function decryptHistorical() {
        var pending = list.querySelectorAll(".e2ee-pending[data-ct]");
        pending.forEach(function (el) {
            var ct = el.dataset.ct;
            var ep = el.dataset.ep;
            var iv = el.dataset.iv;
            if (!ct || !ep || !iv) return;
            E2EE.decrypt(ep, iv, ct).then(function (plain) {
                if (!el.parentNode) return; // element was removed
                if (plain !== null) {
                    el.className  = "message-text";
                    el.innerHTML  = escapeHtml(plain);
                } else {
                    el.className  = "message-text e2ee-fail";
                    el.innerHTML  = '<em>Unable to decrypt message</em>';
                }
            });
        });
    }

    /* ── Auto-decrypt images and small E2EE files on page load ── */
    function decryptHistoricalFiles() {
        var btns = list.querySelectorAll('.e2ee-dl-btn[data-auto-decrypt="1"]');
        btns.forEach(function (btn) { decryptAndRender(btn); });
    }

    /* ── Render voice message bubbles for server-rendered placeholders ── */
    function renderHistoricalVoiceBubbles() {
        if (typeof VoiceMessageBubble === "undefined") return;
        list.querySelectorAll(".vm-bubble-placeholder").forEach(function (el) {
            var fileId = Number(el.dataset.fileId);
            if (!fileId) return;
            el.outerHTML = VoiceMessageBubble.renderBubble(fileId, 0);
        });
    }

    /* ── Init ── */
    filterMessages();
    initPreviews();
    list.scrollTop = list.scrollHeight;

    // ── Voice chat wiring ───────────────────────────────────────────────────
    var _callTimerInterval = null;
    var _callStartTime     = null;
    var _ringtoneInterval  = null;

    function _updateCallTimer() {
        var el = document.getElementById("voice-bar-timer");
        if (!_callStartTime || !el) return;
        var s   = Math.floor((Date.now() - _callStartTime) / 1000);
        var m   = Math.floor(s / 60);
        var sec = String(s % 60).padStart(2, "0");
        el.textContent = m + ":" + sec;
    }

    function _startRingtone() {
        _stopRingtone();
        _ringtoneInterval = setInterval(function () {
            try {
                var ctx  = new AudioContext();
                var osc  = ctx.createOscillator();
                var gain = ctx.createGain();
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.frequency.value = 440;
                gain.gain.setValueAtTime(0.3, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.5);
                osc.start();
                osc.stop(ctx.currentTime + 0.5);
            } catch (_) {}
        }, 1200);
    }

    function _stopRingtone() {
        if (_ringtoneInterval) { clearInterval(_ringtoneInterval); _ringtoneInterval = null; }
    }

    function _handleVoiceStateChange(state, peerId, peerName) {
        var incoming  = document.getElementById("voice-incoming");
        var activeBar = document.getElementById("voice-active-bar");
        var barPeer   = document.getElementById("voice-bar-peer");
        var barStatus = document.getElementById("voice-bar-status");
        var callBtn   = document.getElementById("call-btn");

        if (incoming)  incoming.style.display  = "none";
        if (activeBar) activeBar.style.display = "none";
        clearInterval(_callTimerInterval);
        _callTimerInterval = null;

        if (state === "ringing") {
            var callerNameEl = document.getElementById("voice-caller-name");
            if (callerNameEl) callerNameEl.textContent = peerName || "Unknown";
            if (incoming) incoming.style.display = "flex";
            _startRingtone();

        } else if (state === "calling") {
            if (barPeer)   barPeer.textContent   = peerName || "";
            if (barStatus) barStatus.textContent = "Calling…";
            if (activeBar) activeBar.style.display = "flex";
            if (callBtn)   callBtn.classList.add("in-call");

        } else if (state === "in_call") {
            _stopRingtone();
            if (barPeer)   barPeer.textContent   = peerName || "";
            if (barStatus) barStatus.textContent = "Connected";
            if (activeBar) activeBar.style.display = "flex";
            if (callBtn)   callBtn.classList.add("in-call");
            _callStartTime     = Date.now();
            _callTimerInterval = setInterval(_updateCallTimer, 1000);

        } else if (state === "ended") {
            _stopRingtone();
            if (barPeer)   barPeer.textContent   = peerName || "";
            if (barStatus) barStatus.textContent = "Call ended";
            if (activeBar) activeBar.style.display = "flex";
            if (callBtn)   callBtn.classList.remove("in-call");
            setTimeout(function () { if (activeBar) activeBar.style.display = "none"; }, 2000);

        } else {
            _stopRingtone();
            if (callBtn) callBtn.classList.remove("in-call");
        }
    }

    if (typeof VoiceChat !== "undefined") {
        VoiceChat.setSocketSend(function (event, data) {
            if (!socket || socket.readyState !== WebSocket.OPEN) return;
            socket.send("42" + JSON.stringify([event, data]));
        });
        VoiceChat.onStateChange(_handleVoiceStateChange);
        VoiceChat.onDecline(function (reason) {
            setStatus(reason === "busy" ? "User is busy." : "Call declined.");
        });

        var callBtn = document.getElementById("call-btn");
        if (callBtn) {
            callBtn.addEventListener("click", function () {
                if (!activeChatId || activeChatId === "broadcast") return;
                if (VoiceChat.state !== "idle") {
                    VoiceChat.endCall();
                } else {
                    VoiceChat.startCall(Number(activeChatId), activeChatName).catch(function (err) {
                        setStatus(err.message || "Could not start call.");
                    });
                }
            });
        }

        var voiceMuteBtn = document.getElementById("voice-mute-btn");
        if (voiceMuteBtn) {
            voiceMuteBtn.addEventListener("click", function () {
                var muted = VoiceChat.isMuted();
                VoiceChat.setMuted(!muted);
                voiceMuteBtn.classList.toggle("muted", !muted);
                voiceMuteBtn.setAttribute("aria-label", muted ? "Mute microphone" : "Unmute microphone");
                var svgPath = voiceMuteBtn.querySelector("path");
                if (svgPath) {
                    // swap to mic-off icon when muting
                    var micOn  = 'M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z';
                    var micOff = 'M1 1l22 22M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6';
                    svgPath.setAttribute("d", muted ? micOn : micOff);
                }
            });
        }

        var voiceEndBtn = document.getElementById("voice-end-btn");
        if (voiceEndBtn) {
            voiceEndBtn.addEventListener("click", function () { VoiceChat.endCall(); });
        }

        var voiceAcceptBtn = document.getElementById("voice-accept-btn");
        if (voiceAcceptBtn) {
            voiceAcceptBtn.addEventListener("click", function () { VoiceChat.acceptCall(); });
        }

        var voiceDeclineBtn = document.getElementById("voice-decline-btn");
        if (voiceDeclineBtn) {
            voiceDeclineBtn.addEventListener("click", function () { VoiceChat.declineCall(); });
        }
    }

    // ── Desktop notification wiring ─────────────────────────────────────────
    if (typeof Notify !== "undefined") {
        Notify.init();
        Notify.setOpenChat(function (chatId) {
            var row = document.querySelector('.conversation-row[data-chat-id="' + chatId + '"]');
            if (row) setActiveChat(row);
        });
    }

    // ── P2P transfer wiring ─────────────────────────────────────────────────
    if (typeof P2PTransfer !== "undefined") {
        P2PTransfer.setSocketSend(_sendP2PEvent);
        P2PTransfer.onIncoming(function (transferId, meta) {
            E2EE.whenReady().then(function () {
                _showP2PIncoming(transferId, meta);
            });
        });
    }

    connectSocket();

    // Update fingerprint badge when verification state changes
    document.addEventListener("fingerprint:updated", function (e) {
        var uid = String(e.detail.userId);
        if (uid === String(activeChatId) && chatTitleEl && typeof Fingerprint !== "undefined") {
            chatTitleEl.innerHTML = escapeHtml(activeChatName) + " " + Fingerprint.inlineBadge(uid);
        }
    });

    // Warn when a previously-verified contact's key changes
    document.addEventListener("fingerprint:mismatch", function (e) {
        var row = document.querySelector('[data-chat-id="' + e.detail.userId + '"]');
        var uname = row ? (row.dataset.chatName || "A contact") : "A contact";
        setStatus("⚠ " + escapeHtml(uname) + "'s key changed — verify their fingerprint before sending.");
    });

    if (typeof VoiceMessageBubble !== "undefined") {
        VoiceMessageBubble.setDecryptFn(function (fileId, cb) {
            return FileE2EE.downloadAndDecrypt(fileId, cb);
        });
    }

    renderHistoricalVoiceBubbles();

    // Initialise E2EE: generate/load keypair, register pubkey, then decrypt history
    E2EE.init().then(function () {
        decryptHistorical();
        decryptHistoricalFiles();
    });
})();
