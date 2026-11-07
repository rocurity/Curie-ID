(function () {
  const C = window.Curie;
  const app = document.getElementById("app");

  const LABELS = {
    account_created: "Account created",
    login_success: "Signed in",
    login_failed: "Failed sign-in attempt",
    device_added: "New device confirmed",
    logout: "Signed out",
    password_changed: "Password changed",
    password_reset: "Password reset",
    session_revoked: "Session signed out",
    sessions_revoked_others: "Other sessions signed out",
    sessions_revoked_all: "Signed out everywhere",
    device_removed: "Device removed",
    backup_codes_regenerated: "New backup codes made",
    app_approved: "Approved an app",
    app_signed_in: "Signed in to an app",
    app_disconnected: "App disconnected",
  };

  document.getElementById("signout").addEventListener("click", async () => {
    try { await C.api("/auth/logout", { method: "POST" }); } catch { /* already ended */ }
    C.clearToken();
    location.href = "signin.html";
  });

  async function load() {
    if (!C.token()) return (location.href = "signin.html");
    try {
      const [me, sess, devs, sec, act, apps] = await Promise.all([
        C.api("/me"), C.api("/me/sessions"), C.api("/me/devices"),
        C.api("/me/security"), C.api("/me/activity"), C.api("/me/connected-apps"),
      ]);
      render(me, sess.sessions, devs.devices, sec.backupCodesLeft, act.events, apps.apps);
    } catch (err) {
      if (err.status === 401) { C.clearToken(); return (location.href = "signin.html"); }
      app.innerHTML = `<section><p class="status bad">${C.esc(err.message)}</p></section>`;
    }
  }

  function render(me, sessions, devices, backupLeft, events, apps) {
    const here = C.deviceId();
    app.innerHTML = `
      <section>
        <h2>Profile</h2>
        <p class="muted">Curie ID <strong>${C.esc(me.curieId)}</strong></p>
        <form id="profile">
          <label>Name<input name="displayName" maxlength="60" required value="${C.esc(me.displayName)}"></label>
          <label>Username<input name="username" pattern="[a-z0-9_]{3,20}" required value="${C.esc(me.username)}"></label>
          <label>Gender<select name="gender">
            ${[["", "Prefer not to say"], ["female", "Female"], ["male", "Male"], ["other", "Other"]]
              .map(([v, l]) => `<option value="${v}"${(me.gender || "") === v ? " selected" : ""}>${l}</option>`).join("")}
          </select></label>
          <p class="muted">Email: ${C.esc(me.email)} · Date of birth: ${C.esc(me.dateOfBirth)} (to change these, contact support)</p>
          <button>Save changes</button><p class="status"></p>
        </form>
      </section>

      <section>
        <h2>Change password</h2>
        <form id="password">
          <label>Current password<input name="currentPassword" type="password" required autocomplete="current-password"></label>
          <label>New password<input name="newPassword" type="password" minlength="8" required autocomplete="new-password"></label>
          <button>Change password</button><p class="status"></p>
        </form>
        <p class="muted">Changing your password signs out your other sessions.</p>
      </section>

      <section>
        <h2>Backup codes</h2>
        <p class="muted">You have <strong>${backupLeft}</strong> unused. Each one resets your password once, even without email. Making new codes replaces the old ones.</p>
        <form id="backup">
          <label>Your password<input name="password" type="password" required autocomplete="current-password"></label>
          <button>Make new codes</button><p class="status"></p>
        </form>
        <div id="codes"></div>
      </section>

      <section>
        <h2>Connected apps</h2>
        <p class="muted">Apps you've let sign you in with Curie ID. Disconnecting an app signs you out of it.</p>
        <ul>${apps.map((a) => `
          <li><span><strong>${C.esc(a.name)}</strong>
            <br><span class="muted">Connected ${C.fmt(a.grantedAt)}</span></span>
            <button class="ghost" data-app="${C.esc(a.clientId)}">Disconnect</button></li>`).join("")
          || "<li class='muted'>No connected apps.</li>"}</ul>
      </section>

      <section>
        <h2>Where you're signed in</h2>
        <ul>${sessions.map((s) => `
          <li><span>${s.isCurrent ? "<strong>This session</strong>" : "Another session"}
            ${s.deviceId === here ? " · this browser" : ""}<br>
            <span class="muted">Last active ${C.fmt(s.lastUsedAt)}</span></span>
            ${s.isCurrent ? "" : `<button class="ghost" data-session="${C.esc(s.sid)}">Sign out</button>`}</li>`).join("")
          || "<li class='muted'>No other sessions.</li>"}</ul>
        <div class="actions">
          <button class="ghost" id="signout-others">Sign out other sessions</button>
          <button class="danger" id="signout-all">Sign out everywhere</button>
        </div>
      </section>

      <section>
        <h2>Trusted devices</h2>
        <p class="muted">A new device needs a code emailed to you. Removing a device also signs out its sessions.</p>
        <ul>${devices.map((d) => `
          <li><span>${d.deviceId === here ? "<strong>This browser</strong>" : "Device"}
            <br><span class="muted">Added ${C.fmt(d.addedAt)}</span></span>
            ${d.deviceId === here
              ? '<span class="muted">Use Sign out above to end this browser\'s session.</span>'
              : `<button class="ghost" data-device="${C.esc(d.deviceId)}">Remove</button>`}</li>`).join("")}</ul>
      </section>

      <section>
        <h2>Recent activity</h2>
        <ul>${events.map((ev) => `
          <li><span>${C.esc(LABELS[ev.type] || String(ev.type).replace(/_/g, " "))}</span>
            <span class="muted">${C.fmt(ev.createdAt)}</span></li>`).join("")
          || "<li class='muted'>Nothing yet.</li>"}</ul>
      </section>`;

    document.getElementById("profile").addEventListener("submit", (e) => C.submit(e, async (fd) => {
      await C.api("/me", {
        method: "PATCH",
        body: { displayName: fd.get("displayName"), username: fd.get("username"), gender: fd.get("gender") || null },
      });
      return "Saved.";
    }));

    document.getElementById("password").addEventListener("submit", (e) => C.submit(e, async (fd) => {
      const r = await C.api("/me/password", {
        body: { currentPassword: fd.get("currentPassword"), newPassword: fd.get("newPassword") },
      });
      e.target.reset();
      return `Password changed. ${r.sessionsEnded} other session(s) signed out.`;
    }));

    document.getElementById("backup").addEventListener("submit", (e) => C.submit(e, async (fd) => {
      const r = await C.api("/account/backup-codes", { body: { password: fd.get("password") } });
      e.target.reset();
      document.getElementById("codes").innerHTML = `
        <h3>Your new backup codes</h3>
        <p class="muted"><strong>Save these now.</strong> They won't be shown again.</p>
        <pre>${r.codes.map((c) => C.esc(c)).join("\n")}</pre>`;
      return "New codes made.";
    }));

    document.getElementById("signout-others").addEventListener("click", async () => {
      try { await C.api("/me/sessions/revoke-others", { method: "POST" }); load(); }
      catch (err) { alert(err.message); }
    });

    document.getElementById("signout-all").addEventListener("click", async () => {
      if (!confirm("Sign out everywhere? This also signs out this browser.")) return;
      try { await C.api("/me/sessions/revoke-all", { method: "POST" }); } catch { /* ended anyway */ }
      C.clearToken();
      location.href = "signin.html";
    });

    app.onclick = async (e) => {
      const sessionBtn = e.target.closest("[data-session]");
      const deviceBtn = e.target.closest("[data-device]");
      const appBtn = e.target.closest("[data-app]");
      try {
        if (sessionBtn) {
          await C.api(`/me/sessions/${encodeURIComponent(sessionBtn.dataset.session)}/revoke`, { method: "POST" });
        } else if (deviceBtn) {
          if (!confirm("Remove this device? Signing in from it again will need a code.")) return;
          await C.api(`/me/devices/${encodeURIComponent(deviceBtn.dataset.device)}/revoke`, { method: "POST" });
        } else if (appBtn) {
          if (!confirm("Disconnect this app? It will be signed out and will need your approval to sign in again.")) return;
          await C.api(`/me/connected-apps/${encodeURIComponent(appBtn.dataset.app)}`, { method: "DELETE" });
        } else {
          return;
        }
        load();
      } catch (err) {
        alert(err.message);
      }
    };
  }

  load();
})();
