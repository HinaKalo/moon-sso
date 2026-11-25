// Small progressive enhancements. No inline scripts are allowed by the CSP,
// so behaviour is attached through data attributes.
(function () {
  "use strict";
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (!btn) return;
    var target = document.getElementById(btn.getAttribute("data-copy"));
    if (!target || !navigator.clipboard) return;
    navigator.clipboard.writeText(target.textContent.trim()).then(function () {
      var old = btn.textContent;
      btn.textContent = "已复制";
      setTimeout(function () { btn.textContent = old; }, 1500);
    });
  });
  // Keep the CSRF token on HTMX requests that are not forms (hx-delete etc.).
  document.addEventListener("htmx:configRequest", function (ev) {
    var meta = document.querySelector('input[name="_csrf"]');
    if (meta && !ev.detail.headers["X-CSRF-Token"]) ev.detail.headers["X-CSRF-Token"] = meta.value;
  });
  // Server errors render a fragment; show it at the top if the target vanished.
  document.addEventListener("htmx:sendError", function () {
    alert("网络连接失败，请检查网络后重试");
  });
})();
