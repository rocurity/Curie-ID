(function () {
  const API = (window.CURIE_API || "").replace(/\/$/, "");
  const KEY = "curieAdminKey";
  const app = document.getElementById("app");
  const signout = document.getElementById("signout");
  let lastQuery = "";

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
  const fmt = (v) => (v ? new Date(v).toLocaleString() : "—");
  const key = () => sessionStorage.getItem(KEY);

  const LABELS = {
    account_created: "Account created",
    login_success: "Signed in",
    login_failed: "Failed sign-in attempt",
    device_added: "New device confirmed",
    device_removed: "Device removed",
    logout: "Signed out",
    password_changed: "Password changed",
    password_reset: "Password reset",
    session_revoked: "Session signed out",
    sessions_revoked_others: "Other sessions signed out",
    sessions_revoked_all: "Signed out everywhere",
    backup_codes_regenerated: "New backup codes made",
    app_approved: "Approved an app",
    app_signed_in: "Signed in to an app",
    app_disconnected: "App disconnected",
    admin_suspended: "Suspended by admin",
    admin_restored: "Restored by admin",
    admin_signed_out: "Signed out everywhere by admin",
  };
  const label = (t) => LABELS[t] || String(t).replace(/_/g, " ");

  async function api(path, opts = {}) {
    const r = await fetch(API + path, {
      method: opts.method || (opts.body ? "POST" : "GET"),
      headers: { "Content-Type": "application/json", "X-Admin-Token": key() || "" },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const err = new Error(data.error || "Something went wrong.");
      err.status = r.status;
      throw err;
    }
    return data;
  }

  signout.addEventListener("click", () => { sessionStorage.removeItem(KEY); showLogin(); });
  key() ? home() : showLogin();

  function showLogin(msg) {
    signout.hidden = true;
    app.innerHTML = `
      <section class="card">
        <h2>Admin sign-in</h2>
        <form id="login" class="form">
          <label>Admin key<input name="key" type="password" required autocomplete="off"></label>
          <div class="row"><button>Enter</button></div>
          <p class="status bad">${esc(msg || "")}</p>
        </form>
      </section>`;
    document.getElementById("login").addEventListener("submit", async (e) => {
      e.preventDefault();
      sessionStorage.setItem(KEY, new FormData(e.target).get("key"));
      try {
        await api("/admin/activity");
        home();
      } catch (err) {
        sessionStorage.removeItem(KEY);
        showLogin(err.status === 401 ? "That key isn't right." : err.message);
      }
    });
  }

  function home() {
    signout.hidden = false;
    app.innerHTML = `
      <section class="card">
        <form id="search" class="row">
          <input name="q" placeholder="Search by Curie ID, username, name or email" autocomplete="off">
          <button>Search</button>
        </form>
        <div id="results" style="margin-top:.8rem"></div>
      </section>
      <div id="detail"></div>
      <section class="card">
        <h2>Recent activity</h2>
        <div id="activity"></div>
      </section>`;
    document.getElementById("search").addEventListener("submit", (e) => {
      e.preventDefault();
      search(new FormData(e.target).get("q").trim());
    });
    search("");
    loadActivity();
  }

  async function search(q) {
    lastQuery = q;
    const box = document.getElementById("results");
    box.innerHTML = "Loading…";
    try {
      const { users } = await api("/admin/users" + (q ? "?q=" + encodeURIComponent(q) : ""));
      box.innerHTML = users.length
        ? `<table>
             <thead><tr><th>Curie ID</th><th>Name</th><th>Username</th><th>Email</th><th>Status</th><th>Joined</th></tr></thead>
             <tbody>${users.map((u) => `
               <tr data-id="${esc(u.curieId)}">
                 <td>${esc(u.curieId)}</td><td>${esc(u.displayName)}</td><td>${esc(u.username)}</td>
                 <td>${esc(u.email)}</td>
                 <td><span class="tag ${esc(u.status)}">${esc(u.status)}</span></td>
                 <td>${fmt(u.createdAt)}</td>
               </tr>`).join("")}</tbody>
           </table>`
        : "<p class='muted'>No accounts found.</p>";
      box.querySelectorAll("tr[data-id]").forEach((tr) => {
        tr.addEventListener("click", () => detail(tr.dataset.id));
      });
    } catch (err) {
      box.innerHTML = `<p class="status bad">${esc(err.message)}</p>`;
    }
  }

  async function detail(id) {
    const d = await api(`/admin/users/${encodeURIComponent(id)}`);
    const u = d.user;
    const box = document.getElementById("detail");
    box.innerHTML = `
      <section class="card">
        <h2>${esc(u.displayName)} <span class="muted">@${esc(u.username)}</span></h2>
        <p>Curie ID <strong>${esc(u.curieId)}</strong> · <span class="tag ${esc(u.status)}">${esc(u.status)}</span></p>
        <p class="muted">Email ${esc(u.email)} · Date of birth ${esc(u.dateOfBirth)} · Gender ${esc(u.gender || "not given")}</p>
        <p class="muted">Joined ${fmt(u.createdAt)} · ${d.activeSessions} active session(s) · ${d.trustedDevices} trusted device(s) · ${u.backupCodesLeft} backup code(s) left</p>
        <div class="row" style="margin:.8rem 0">
          ${u.status === "suspended"
            ? '<button data-act="restore">Restore account</button>'
            : '<button class="danger" data-act="suspend">Suspend account</button>'}
          <button class="ghost" data-act="signout">Sign out everywhere</button>
          <button class="ghost" data-act="close">Close</button>
        </div>
        <p class="status" id="detail-status"></p>
        <h3>Connected apps</h3>
        <ul>${d.connectedApps.map((a) => `<li>${esc(a.name)} <span class="muted">since ${fmt(a.grantedAt)}</span></li>`).join("") || "<li class='muted'>None</li>"}</ul>
        <h3>Recent activity</h3>
        <ul>${d.events.map((ev) => `<li>${esc(label(ev.type))} <span class="muted">${fmt(ev.createdAt)}</span></li>`).join("") || "<li class='muted'>Nothing yet</li>"}</ul>
      </section>`;
    box.scrollIntoView({ behavior: "smooth" });
    box.onclick = async (e) => {
      const act = e.target.closest("[data-act]")?.dataset.act;
      if (!act) return;
      if (act === "close") { box.innerHTML = ""; return; }
      const status = document.getElementById("detail-status");
      try {
        if (act === "suspend" || act === "restore") {
          if (act === "suspend" && !confirm("Suspend this account? Its sessions will end, and it can't sign in until restored.")) return;
          await api(`/admin/users/${encodeURIComponent(id)}/status`, {
            body: { status: act === "suspend" ? "suspended" : "active" },
          });
        } else if (act === "signout") {
          if (!confirm("Sign this account out everywhere?")) return;
          const r = await api(`/admin/users/${encodeURIComponent(id)}/revoke-sessions`, { method: "POST" });
          status.textContent = `${r.sessionsEnded} session(s) ended.`;
          return;
        }
        await detail(id);
        search(lastQuery);
        loadActivity();
      } catch (err) {
        status.textContent = err.message;
        status.className = "status bad";
      }
    };
  }

  async function loadActivity() {
    const box = document.getElementById("activity");
    try {
      const { events } = await api("/admin/activity");
      box.innerHTML = `<ul>${events.map((ev) => `
        <li><span class="muted">${fmt(ev.createdAt)}</span> &nbsp; ${esc(ev.curieId)} · ${esc(label(ev.type))}</li>`).join("")
        || "<li class='muted'>Nothing yet.</li>"}</ul>`;
    } catch (err) {
      box.innerHTML = `<p class="status bad">${esc(err.message)}</p>`;
    }
  }
})();
