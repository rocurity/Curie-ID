(function () {
  const C = window.Curie;
  const app = document.getElementById("app");
  const enc = encodeURIComponent;
  let pending = null; // { clientId, clientSecret } shown once

  const lines = (v) => String(v || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

  document.getElementById("signout").addEventListener("click", async () => {
    try { await C.api("/auth/logout", { method: "POST" }); } catch { /* already ended */ }
    C.clearToken();
    location.href = "signin.html";
  });

  async function load() {
    if (!C.token()) {
      app.innerHTML = `<section class="card"><h2>Sign in first</h2>
        <p><a href="signin.html">Sign in to Curie ID</a>, then come back here.</p></section>`;
      return;
    }
    try {
      const { apps } = await C.api("/dev/apps");
      render(apps);
    } catch (err) {
      if (err.status === 401) { C.clearToken(); return load(); }
      app.innerHTML = `<section class="card"><p class="status bad">${C.esc(err.message)}</p></section>`;
    }
  }

  function secretBox(p) {
    return `
      <section class="card secret">
        <h2>Save these now</h2>
        <p class="muted">The client secret is shown once. If you lose it, rotate it to get a new one.</p>
        <p>Client ID <code>${C.esc(p.clientId)}</code></p>
        ${p.clientSecret ? `<p>Client secret <code>${C.esc(p.clientSecret)}</code></p>` : ""}
        <div class="actions"><button id="dismiss">I've saved them</button></div>
      </section>`;
  }

  function card(a) {
    return `
      <article class="app" data-id="${C.esc(a.clientId)}">
        <header>
          <strong>${C.esc(a.name)}</strong>
          <span class="tag">${a.type === "confidential" ? "Server app" : "Browser or mobile app"}</span>
        </header>
        <p class="muted">Client ID <code>${C.esc(a.clientId)}</code> · ${a.connectedUsers} connected user(s)</p>
        <form class="edit">
          <label>Redirect addresses
            <textarea name="redirectUris" rows="2">${C.esc(a.redirectUris.join("\n"))}</textarea>
            <span class="muted">One per line. Each must match exactly the address your app uses.</span></label>
          <div class="actions">
            <button>Save addresses</button>
            ${a.type === "confidential" ? '<button type="button" class="ghost" data-rotate>Rotate secret</button>' : ""}
            <button type="button" class="danger" data-delete>Delete app</button>
          </div>
          <p class="status"></p>
        </form>
      </article>`;
  }

  function snippet(clientId) {
    const api = (window.CURIE_API || "").replace(/\/$/, "");
    const pages = location.origin;
    return [
      "// 1. Make a random verifier, and its challenge (in the browser)",
      "const verifier = randomString(64);",
      "const challenge = base64url(await sha256(verifier));",
      "",
      "// 2. Send the user to Curie ID",
      `const u = new URL("${pages}/authorize.html");`,
      `u.search = new URLSearchParams({ client_id: "${clientId}", redirect_uri: REDIRECT,`,
      "  code_challenge: challenge, code_challenge_method: \"S256\", state }).toString();",
      "location.href = u;",
      "",
      "// 3. On your redirect page, exchange the code for a token",
      `const t = await fetch("${api}/oauth/token", {`,
      "  method: \"POST\",",
      "  headers: { \"Content-Type\": \"application/x-www-form-urlencoded\" },",
      `  body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT,`,
      `    client_id: "${clientId}", code_verifier: verifier }) }).then(r => r.json());`,
      "",
      "// 4. Read who the user is",
      `const me = await fetch("${api}/oauth/userinfo", {`,
      "  headers: { Authorization: \"Bearer \" + t.access_token } }).then(r => r.json());",
      "// me.sub is the user's Curie ID, me.name and me.preferred_username are their name and username",
    ].join("\n");
  }

  function render(apps) {
    app.innerHTML = `
      ${pending ? secretBox(pending) : ""}
      <section class="card" id="apps">
        <h2>Your apps</h2>
        ${apps.length ? apps.map(card).join("") : "<p class='muted'>You haven't registered an app yet. Create one below.</p>"}
      </section>

      <section class="card" id="register">
        <h2>Register an app</h2>
        <form id="new">
          <label>App name<input name="name" maxlength="60" required></label>
          <fieldset>
            <legend>Type</legend>
            <label><input type="radio" name="type" value="public" checked> Browser or mobile app
              <span class="muted">(no secret, uses PKCE)</span></label>
            <label><input type="radio" name="type" value="confidential"> Server app
              <span class="muted">(gets a secret, keep it on your server)</span></label>
          </fieldset>
          <label>Redirect addresses
            <textarea name="redirectUris" rows="3" required placeholder="https://yourapp.example/callback"></textarea>
            <span class="muted">One per line. https:// only, or http://localhost while testing.</span></label>
          <div class="actions"><button>Create app</button></div>
          <p class="status"></p>
        </form>
      </section>

      <section class="card" id="connect">
        <h2>How to connect</h2>
        <p class="muted">Use your app's client ID in the code below. Full guide: DEVELOPERS.md.</p>
        <pre>${C.esc(snippet(apps[0] ? apps[0].clientId : "YOUR_CLIENT_ID"))}</pre>
      </section>`;
  }

  async function createApp(fd) {
    pending = await C.api("/dev/apps", {
      body: { name: fd.get("name"), type: fd.get("type"), redirectUris: lines(fd.get("redirectUris")) },
    });
    await load();
    return "";
  }

  async function saveApp(fd, form) {
    const id = form.closest(".app").dataset.id;
    await C.api(`/dev/apps/${enc(id)}`, { method: "PATCH", body: { redirectUris: lines(fd.get("redirectUris")) } });
    return "Saved.";
  }

  app.addEventListener("submit", (e) => {
    if (e.target.id === "new") return C.submit(e, createApp);
    if (e.target.matches(".edit")) return C.submit(e, saveApp);
  });

  app.addEventListener("click", async (e) => {
    if (e.target.id === "dismiss") { pending = null; return load(); }
    const card = e.target.closest(".app");
    if (!card) return;
    const id = card.dataset.id;
    try {
      if (e.target.matches("[data-rotate]")) {
        if (!confirm("Rotate the secret? The old one stops working immediately, so update your server first.")) return;
        const r = await C.api(`/dev/apps/${enc(id)}/rotate-secret`, { method: "POST" });
        pending = { clientId: r.clientId, clientSecret: r.clientSecret };
        return load();
      }
      if (e.target.matches("[data-delete]")) {
        if (!confirm("Delete this app? Everyone signed in through it will be signed out.")) return;
        await C.api(`/dev/apps/${enc(id)}`, { method: "DELETE" });
        return load();
      }
    } catch (err) {
      alert(err.message);
    }
  });

  load();
})();
