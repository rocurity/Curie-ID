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
    email_changed: "Email address changed",
  };
  const GENDERS = [["", "Prefer not to say"], ["female", "Female"], ["male", "Male"], ["other", "Other"]];

  document.getElementById("signout").addEventListener("click", async () => {
    try { await C.api("/auth/logout", { method: "POST" }); } catch { /* already ended */ }
    C.clearToken();
    location.href = "index.html";
  });

  async function load() {
    if (!C.token()) return (location.href = "index.html");
    try {
      const [me, sess, devs, sec, act, apps] = await Promise.all([
        C.api("/me"), C.api("/me/sessions"), C.api("/me/devices"),
        C.api("/me/security"), C.api("/me/activity"), C.api("/me/connected-apps"),
      ]);
      render({
        me, sessions: sess.sessions, devices: devs.devices,
        backupLeft: sec.backupCodesLeft, events: act.events, apps: apps.apps,
      });
    } catch (err) {
      if (err.status === 401) { C.clearToken(); return (location.href = "index.html"); }
      app.innerHTML = `<section class="card"><p class="status bad">${C.esc(err.message)}</p></section>`;
    }
  }

  // A row that opens to show a form or more detail
  function item(title, value, body, open) {
    return `
      <details class="item"${open ? " open" : ""}>
        <summary>
          <div class="item-text">
            <div class="item-title">${title}</div>
            <div class="item-value">${value}</div>
          </div>
        </summary>
        <div class="item-body">${body}</div>
      </details>`;
  }

  // A row that only shows information
  function staticRow(title, value, note) {
    return `
      <div class="item static">
        <div class="item-text">
          <div class="item-title">${title}</div>
          <div class="item-value">${value}</div>
          ${note ? `<div class="item-note">${note}</div>` : ""}
        </div>
      </div>`;
  }

  const PARTS = ["home", "personal", "security", "apps", "activity"];

  // Only the part named in the address (#security etc.) is shown; Home is the default
  function showPart() {
    const wanted = (location.hash || "#home").slice(1);
    const id = PARTS.includes(wanted) ? wanted : "home";
    document.querySelectorAll("section.group").forEach((sec) => { sec.hidden = sec.id !== id; });
    document.querySelectorAll(".side-link").forEach((a) => {
      a.setAttribute("aria-current", a.getAttribute("href") === "#" + id ? "page" : "false");
    });
    window.scrollTo(0, 0);
  }
  window.addEventListener("hashchange", showPart);

  function render(d) {
    const here = C.deviceId();
    const me = d.me;
    const initial = (me.displayName || me.username || "C").trim().charAt(0).toUpperCase();
    const genderName = (GENDERS.find(([v]) => v === (me.gender || "")) || GENDERS[0])[1];

    const passwordBody = `
      <form id="password">
        <label>Current password<input name="currentPassword" type="password" required autocomplete="current-password"></label>
        <label>New password<input name="newPassword" type="password" minlength="8" required autocomplete="new-password">
          <span class="muted">At least 8 characters, with letters and numbers.</span></label>
        <div class="actions"><button>Change password</button></div>
        <p class="status"></p>
      </form>
      <p class="item-note">Changing your password signs out your other sessions.</p>`;

    const emailBody = `
      <form id="email-start">
        <label>New email address<input name="newEmail" type="email" required autocomplete="email"></label>
        <label>Your password<input name="password" type="password" required autocomplete="current-password"></label>
        <div class="actions"><button>Send code to new address</button></div>
        <p class="status"></p>
      </form>
      <form id="email-confirm" hidden>
        <p id="email-sent" class="muted"></p>
        <label>6-digit code<input name="code" inputmode="numeric" maxlength="6" required></label>
        <div class="actions"><button>Confirm new email</button><button type="button" class="ghost" id="email-cancel">Cancel</button></div>
        <p class="status"></p>
      </form>`;

    const backupBody = `
      <p class="item-note">Each code resets your password once, even without email. Making new codes replaces the old ones.</p>
      <form id="backup">
        <label>Your password<input name="password" type="password" required autocomplete="current-password"></label>
        <div class="actions"><button>Make new codes</button></div>
        <p class="status"></p>
      </form>
      <div id="codes"></div>`;

    const devicesBody = `
      <ul class="plain">${d.devices.map((x) => `
        <li><span>${x.deviceId === here ? "<strong>This browser</strong>" : "Device"}
          <br><span class="muted">Added ${C.fmt(x.addedAt)}</span></span>
          ${x.deviceId === here
            ? '<span class="muted">Use Sign out in the sidebar to end this session.</span>'
            : `<button class="ghost" data-device="${C.esc(x.deviceId)}">Remove</button>`}</li>`).join("")
        || "<li class='muted'>No trusted devices.</li>"}</ul>
      <p class="item-note">A new device needs a code emailed to you. Removing a device also signs out its sessions.</p>`;

    const sessionsBody = `
      <ul class="plain">${d.sessions.map((s) => `
        <li><span>${s.isCurrent ? "<strong>This session</strong>" : "Another session"}
          ${s.deviceId === here ? " · this browser" : ""}<br>
          <span class="muted">Last active ${C.fmt(s.lastUsedAt)}</span></span>
          ${s.isCurrent ? "" : `<button class="ghost" data-session="${C.esc(s.sid)}">Sign out</button>`}</li>`).join("")
        || "<li class='muted'>No other sessions.</li>"}</ul>
      <div class="actions" style="margin-top:.9rem">
        <button class="ghost" id="signout-others">Sign out other sessions</button>
        <button class="danger" id="signout-all">Sign out everywhere</button>
      </div>`;

    const appsBody = `
      <ul class="plain">${d.apps.map((a) => `
        <li><span><strong>${C.esc(a.name)}</strong><br><span class="muted">Connected ${C.fmt(a.grantedAt)}</span></span>
          <button class="ghost" data-app="${C.esc(a.clientId)}">Disconnect</button></li>`).join("")
        || "<li class='muted'>No connected apps.</li>"}</ul>`;

    const eventsBody = `
      <ul class="plain">${d.events.map((ev) => `
        <li><span>${C.esc(LABELS[ev.type] || String(ev.type).replace(/_/g, " "))}</span>
          <span class="muted">${C.fmt(ev.createdAt)}</span></li>`).join("")
        || "<li class='muted'>Nothing yet.</li>"}</ul>`;

    const photoBody = `
      <form id="f-photo">
        <label>Choose a picture<input type="file" name="photo" accept="image/png,image/jpeg,image/webp" required></label>
        <div class="actions">
          <button>Save photo</button>
          ${me.avatarVersion ? '<button type="button" class="ghost" id="photo-remove">Remove photo</button>' : ""}
        </div>
        <p class="status"></p>
        <p class="item-note">A square picture works best. We crop it to a square and resize it to 256 pixels.</p>
      </form>`;

    app.innerHTML = `
      <section class="group" id="home">
        <div class="card hero">
          ${me.avatarVersion
            ? `<img class="avatar-img" alt="" src="${C.API}/avatar/${me.curieId}?v=${me.avatarVersion}">`
            : `<div class="avatar">${C.esc(initial)}</div>`}
          <div>
            <h2>${C.esc(me.displayName)}</h2>
            <p class="muted">@${C.esc(me.username)} · Curie ID ${C.esc(me.curieId)}</p>
          </div>
        </div>
        <div class="stats">
          <div class="stat"><span class="stat-n">${d.backupLeft}</span><span class="stat-l">backup codes left</span></div>
          <div class="stat"><span class="stat-n">${d.devices.length}</span><span class="stat-l">trusted devices</span></div>
          <div class="stat"><span class="stat-n">${d.sessions.length}</span><span class="stat-l">signed-in sessions</span></div>
          <div class="stat"><span class="stat-n">${d.apps.length}</span><span class="stat-l">connected apps</span></div>
        </div>
        ${d.backupLeft === 0
          ? '<p class="item-note" style="margin-top:.9rem">You have no backup codes. <a href="#security">Make some in Sign-in & security</a>.</p>'
          : ""}
      </section>

      <section class="group" id="personal">
        <h2>Personal info</h2>
        <p class="muted">Information you share with apps that use Curie ID.</p>
        <div class="items">
          ${item("Name", C.esc(me.displayName), `
            <form id="f-name">
              <label>Name<input name="displayName" maxlength="60" required value="${C.esc(me.displayName)}"></label>
              <div class="actions"><button>Save</button></div><p class="status"></p>
            </form>`)}
          ${item("Username", "@" + C.esc(me.username), `
            <form id="f-username">
              <label>Username<input name="username" pattern="[a-z0-9_]{3,20}" required value="${C.esc(me.username)}">
                <span class="muted">3 to 20 characters: lowercase letters, numbers and underscores.</span></label>
              <div class="actions"><button>Save</button></div><p class="status"></p>
            </form>`)}
          ${item("Gender", C.esc(genderName), `
            <form id="f-gender">
              <label>Gender<select name="gender">
                ${GENDERS.map(([v, l]) => `<option value="${v}"${(me.gender || "") === v ? " selected" : ""}>${l}</option>`).join("")}
              </select></label>
              <div class="actions"><button>Save</button></div><p class="status"></p>
            </form>`)}
          ${item("Profile photo", me.avatarVersion ? "Set" : "Not set", photoBody)}
          ${staticRow("Date of birth", C.esc(me.dateOfBirth), "To change this, contact support.")}
        </div>
      </section>

      <section class="group" id="security">
        <h2>Sign-in & security</h2>
        <p class="muted">How you sign in, and how to get back in if you lose access.</p>
        <div class="items">
          ${item("Password", "••••••••", passwordBody)}
          ${item("Email address", C.esc(me.email), emailBody)}
          ${item("Backup codes", `${d.backupLeft} left`, backupBody)}
          ${item("Trusted devices", `${d.devices.length} device(s)`, devicesBody)}
          ${item("Signed-in sessions", `${d.sessions.length} active`, sessionsBody)}
        </div>
      </section>

      <section class="group" id="apps">
        <h2>Apps & access</h2>
        <p class="muted">Apps that can sign you in with Curie ID.</p>
        <div class="items">
          ${item("Connected apps", `${d.apps.length} app(s)`, appsBody)}
          <div class="item static"><a class="item-link" href="developers.html">Manage developer apps →</a></div>
        </div>
      </section>

      <section class="group" id="activity">
        <h2>Activity & history</h2>
        <p class="muted">Recent sign-ins and changes to your account.</p>
        <div class="items">
          ${item("Recent activity", `${d.events.length} event(s)`, eventsBody, true)}
        </div>
      </section>`;

    showPart();

    // Personal info: each field saves on its own
    const saveField = (id, body) => document.getElementById(id).addEventListener("submit", (e) =>
      C.submit(e, async (fd) => { await C.api("/me", { method: "PATCH", body: body(fd) }); return "Saved."; }));
    saveField("f-name", (fd) => ({ displayName: fd.get("displayName") }));
    saveField("f-username", (fd) => ({ username: fd.get("username") }));
    saveField("f-gender", (fd) => ({ gender: fd.get("gender") || null }));

    // Profile photo: crop to a square, shrink, then send
    function squareJpeg(file, size) {
      return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
          const side = Math.min(img.width, img.height);
          const canvas = document.createElement("canvas");
          canvas.width = size;
          canvas.height = size;
          canvas.getContext("2d").drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side, 0, 0, size, size);
          URL.revokeObjectURL(img.src);
          resolve(canvas.toDataURL("image/jpeg", 0.86));
        };
        img.onerror = () => reject(new Error("We couldn't read that picture. Try a PNG, JPEG or WebP."));
        img.src = URL.createObjectURL(file);
      });
    }

    document.getElementById("f-photo").addEventListener("submit", (e) => C.submit(e, async (fd) => {
      const file = fd.get("photo");
      if (!file || !file.size) throw new Error("Choose a picture first.");
      if (file.size > 8 * 1024 * 1024) throw new Error("That picture is too big. Choose one under 8 MB.");
      await C.api("/me/avatar", { method: "PUT", body: { data: await squareJpeg(file, 256) } });
      load();
      return "";
    }));

    document.getElementById("photo-remove")?.addEventListener("click", async () => {
      if (!confirm("Remove your profile picture?")) return;
      try { await C.api("/me/avatar", { method: "DELETE" }); load(); }
      catch (err) { alert(err.message); }
    });

    // Sign-in & security
    document.getElementById("password").addEventListener("submit", (e) => C.submit(e, async (fd) => {
      const r = await C.api("/me/password", {
        body: { currentPassword: fd.get("currentPassword"), newPassword: fd.get("newPassword") },
      });
      e.target.reset();
      return `Password changed. ${r.sessionsEnded} other session(s) signed out.`;
    }));

    document.getElementById("email-start").addEventListener("submit", (e) => C.submit(e, async (fd) => {
      const r = await C.api("/me/email/start", { body: { newEmail: fd.get("newEmail"), password: fd.get("password") } });
      document.getElementById("email-start").hidden = true;
      document.getElementById("email-confirm").hidden = false;
      document.getElementById("email-sent").textContent = `We sent a code to ${r.maskedEmail}.`;
      return "";
    }));

    document.getElementById("email-confirm").addEventListener("submit", (e) => C.submit(e, async (fd) => {
      await C.api("/me/email/confirm", { body: { code: fd.get("code") } });
      load();
      return "";
    }));

    document.getElementById("email-cancel").addEventListener("click", async () => {
      try { await C.api("/me/email/cancel", { method: "POST" }); } catch { /* nothing pending */ }
      load();
    });

    document.getElementById("backup").addEventListener("submit", (e) => C.submit(e, async (fd) => {
      const r = await C.api("/account/backup-codes", { body: { password: fd.get("password") } });
      e.target.reset();
      document.getElementById("codes").innerHTML = `
        <h3>Your new backup codes</h3>
        <p class="item-note"><strong>Save these now.</strong> They won't be shown again.</p>
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
      location.href = "index.html";
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
