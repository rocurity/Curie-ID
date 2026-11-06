/* Shared helpers for the Curie ID pages. */
(function () {
  const TOKEN = "curieToken";
  const DEVICE = "curieDeviceId";

  function deviceId() {
    let id = localStorage.getItem(DEVICE);
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem(DEVICE, id);
    }
    return id;
  }
  const token = () => sessionStorage.getItem(TOKEN);
  const setToken = (t) => sessionStorage.setItem(TOKEN, t);
  const clearToken = () => sessionStorage.removeItem(TOKEN);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
  const fmt = (v) => (v ? new Date(v).toLocaleString() : "—");

  /** Calls the API. On 401 it tries one refresh with the stored token. */
  async function api(path, opts = {}, canRefresh = true) {
    const base = (window.CURIE_API || "").replace(/\/$/, "");
    const t = token();
    const res = await fetch(base + path, {
      method: opts.method || (opts.body ? "POST" : "GET"),
      headers: { "Content-Type": "application/json", ...(t ? { Authorization: "Bearer " + t } : {}) },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    if (res.status === 401 && canRefresh && t && !opts.noRefresh) {
      const r = await fetch(base + "/auth/refresh", { method: "POST", headers: { Authorization: "Bearer " + t } });
      if (r.ok) {
        setToken((await r.json()).accessToken);
        return api(path, opts, false);
      }
    }
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    if (!res.ok) {
      const err = new Error(data.error || "Something went wrong. Try again.");
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  /** Runs an async form handler, shows its message, and disables the button while it runs. */
  function submit(e, handler) {
    e.preventDefault();
    const form = e.target;
    const status = form.querySelector(".status");
    const btn = form.querySelector("button");
    if (btn) btn.disabled = true;
    if (status) { status.textContent = ""; status.className = "status"; }
    Promise.resolve()
      .then(() => handler(new FormData(form), form))
      .then((msg) => {
        if (status && msg) { status.textContent = msg; status.classList.add("ok"); }
      })
      .catch((err) => {
        if (status) { status.textContent = err.message; status.classList.add("bad"); }
      })
      .finally(() => { if (btn) btn.disabled = false; });
  }

  window.Curie = { api, token, setToken, clearToken, deviceId, esc, fmt, submit };
})();
