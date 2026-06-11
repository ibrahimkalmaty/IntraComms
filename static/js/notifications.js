// notifications.js
// Desktop push notifications via the browser Notification API.
// Requires a secure context (HTTPS) — the dev server already serves TLS.
//
// Behaviour:
//   - Notifications fire only while the IntraComms window is NOT focused;
//     when you are looking at the app, the in-page UI is enough.
//   - Clicking a notification focuses the window and (for messages/calls)
//     opens the relevant conversation.
//   - A bell button in the navbar toggles notifications on/off (persisted
//     in localStorage) and triggers the browser permission prompt.
//
// Public API:
//   Notify.init()                 mount bell button, arm permission request
//   Notify.setOpenChat(fn)        fn(chatId) — called on notification click
//   Notify.show({title, body, tag, chatId})
//   Notify.enabled() → bool

const Notify = (() => {

  const PREF_KEY = "intracomms_notify";   // "off" = muted; anything else = on

  let _openChat = null;
  let _bellBtn  = null;

  function supported() {
    return "Notification" in window && window.isSecureContext;
  }

  function enabled() {
    return supported()
      && Notification.permission === "granted"
      && localStorage.getItem(PREF_KEY) !== "off";
  }

  function setOpenChat(fn) { _openChat = fn; }

  // ── Show a notification ────────────────────────────────────────────
  // Suppressed while the window is focused — the in-app UI covers that.
  function show(opts) {
    if (!enabled()) return;
    if (document.hasFocus()) return;

    try {
      const n = new Notification(opts.title || "IntraComms", {
        body: opts.body || "",
        tag:  opts.tag  || undefined,   // same tag replaces older notification
        icon: _favicon(),
      });
      n.onclick = function () {
        window.focus();
        if (opts.chatId && _openChat) _openChat(String(opts.chatId));
        n.close();
      };
    } catch (e) {
      // Some platforms (older Android Chrome) only allow notifications
      // from a ServiceWorker registration — fail quietly.
      console.warn("[Notify]", e);
    }
  }

  function _favicon() {
    const link = document.querySelector('link[rel~="icon"]');
    return link ? link.href : undefined;
  }

  // ── Permission ─────────────────────────────────────────────────────
  // Browsers only show the full permission prompt in response to a user
  // gesture, so we request on the first click/keypress anywhere.
  function _armPermissionRequest() {
    if (Notification.permission !== "default") return;
    const ask = function () {
      document.removeEventListener("click", ask);
      document.removeEventListener("keydown", ask);
      Notification.requestPermission().then(_renderBell);
    };
    document.addEventListener("click", ask);
    document.addEventListener("keydown", ask);
  }

  // ── Bell toggle in the navbar ──────────────────────────────────────
  const BELL_ON =
    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"' +
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>' +
    '<path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>';
  const BELL_OFF =
    '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"' +
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M13.73 21a2 2 0 0 1-3.46 0"/>' +
    '<path d="M18.63 13A17.89 17.89 0 0 1 18 8"/>' +
    '<path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14"/>' +
    '<path d="M18 8a6 6 0 0 0-9.33-5"/>' +
    '<line x1="1" y1="1" x2="23" y2="23"/></svg>';

  function _renderBell() {
    if (!_bellBtn) return;
    const muted   = localStorage.getItem(PREF_KEY) === "off";
    const blocked = Notification.permission === "denied";
    const on      = !muted && Notification.permission === "granted";
    _bellBtn.innerHTML = on ? BELL_ON : BELL_OFF;
    _bellBtn.title = blocked
      ? "Notifications blocked — allow them in your browser's site settings"
      : on ? "Notifications on — click to mute"
           : "Notifications off — click to enable";
    _bellBtn.setAttribute("aria-pressed", on ? "true" : "false");
    _bellBtn.style.opacity = blocked ? "0.5" : "";
  }

  function _mountBell() {
    const actions = document.querySelector(".nav-actions");
    if (!actions) return;
    _bellBtn = document.createElement("button");
    _bellBtn.type = "button";
    _bellBtn.className = "btn btn-outline-secondary btn-sm notify-bell";
    _bellBtn.setAttribute("aria-label", "Toggle desktop notifications");
    _bellBtn.addEventListener("click", function (e) {
      e.stopPropagation();
      if (Notification.permission === "default") {
        Notification.requestPermission().then(function (perm) {
          if (perm === "granted") localStorage.removeItem(PREF_KEY);
          _renderBell();
        });
        return;
      }
      const muted = localStorage.getItem(PREF_KEY) === "off";
      if (muted) localStorage.removeItem(PREF_KEY);
      else       localStorage.setItem(PREF_KEY, "off");
      _renderBell();
    });
    actions.insertBefore(_bellBtn, actions.firstElementChild);
    _renderBell();
  }

  function init() {
    if (!supported()) return;
    _mountBell();
    _armPermissionRequest();
  }

  return { init, setOpenChat, show, enabled };
})();
