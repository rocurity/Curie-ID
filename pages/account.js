(function () {
  const C = window.Curie;
  const app = document.getElementById("app");

  document.getElementById("signout").addEventListener("click", async () => {
    try { await C.api("/auth/logout", { method: "POST" }); } catch { /* already ended */ }
    C.clearToken();
    location.href = "signin.html";
  });

  async function load() {
    if (!C.token()) return (location.href = "signin.html");
    try {
      const [me, sess, devs] = await Promise.all([C.api("/me"), C.api("/me/sessions"), C.api("/me/devices")]);
      render(me, sess.sessions, devs.devices);
    } catch (err) {
      if (err.status === 401) { C.clearToken(); return (location.href = "signin.html"); }
      app.innerHTML = `<section><p class="status bad">${C.esc(err.message)}</p></section>`;
    }
  }

  function render(me, sessions, devices) {
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
        <h2>Where you're signed in</h2>
        <ul>${sessions.map((s) => `
          <li><span>${s.isCurrent ? "<strong>This session</strong>" : "Another session"}
            ${s.deviceId === here ? " · this browser" : ""}<br>
            <span class="muted">Last active ${C.fmt(s.lastUsedAt)}</span></span>
            ${s.isCurrent ? "" : `<button class="ghost" data-session="${C.esc(s.sid)}">Sign out</button>`}</li>`).join("")
          || "<li class='muted'>No other sessions.</li>"}</ul>
        <button class="ghost" id="signout-others">Sign out other sessions</button>
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

    document.getElementById("signout-others").addEventListener("click", async () => {
      try { await C.api("/me/sessions/revoke-others", { method: "POST" }); load(); }
      catch (err) { alert(err.message); }
    });

    app.onclick = async (e) => {
      const sessionBtn = e.target.closest("[data-session]");
      const deviceBtn = e.target.closest("[data-device]");
      try {
        if (sessionBtn) {
          await C.api(`/me/sessions/${encodeURIComponent(sessionBtn.dataset.session)}/revoke`, { method: "POST" });
        } else if (deviceBtn) {
          if (!confirm("Remove this device? Signing in from it again will need a code.")) return;
          await C.api(`/me/devices/${encodeURIComponent(deviceBtn.dataset.device)}/revoke`, { method: "POST" });
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
