(function () {
  const C = window.Curie;
  const app = document.getElementById("app");
  const q = new URLSearchParams(location.search);
  const req = {
    clientId: q.get("client_id") || "",
    redirectUri: q.get("redirect_uri") || "",
    codeChallenge: q.get("code_challenge") || "",
    codeChallengeMethod: q.get("code_challenge_method") || "",
    state: q.get("state") || "",
  };
  let appName = "";
  let step = null; // { kind: "device", challengeId } or { kind: "verify", curieId }

  start();

  async function start() {
    if (!req.clientId || !req.redirectUri || !req.codeChallenge || req.codeChallengeMethod !== "S256") {
      return showError("This sign-in link is incomplete. Go back to the app and try again.");
    }
    try {
      new URL(req.redirectUri);
      appName = (await C.api(`/oauth/app?client_id=${encodeURIComponent(req.clientId)}`, { noRefresh: true })).name;
    } catch {
      return showError("This app isn't recognised, so we can't sign you in to it.");
    }
    if (!C.token()) return showSignIn();
    showConsent();
  }

  function showSignIn() {
    app.innerHTML = `
      <section class="card">
        <h1>Sign in to continue to ${C.esc(appName)}</h1>
        <form id="signin">
          <label>Curie ID, username or email<input name="identifier" required autocomplete="username"></label>
          <label>Password<input name="password" type="password" required autocomplete="current-password"></label>
          <div class="actions"><button>Sign in</button></div>
          <p class="status" role="status"></p>
        </form>
        <form id="code" hidden>
          <p id="code-text"></p>
          <label>6-digit code<input name="code" inputmode="numeric" maxlength="6" required></label>
          <div class="actions"><button>Confirm</button></div>
          <p class="status" role="status"></p>
        </form>
      </section>`;
    document.getElementById("signin").addEventListener("submit", (e) => C.submit(e, signIn));
    document.getElementById("code").addEventListener("submit", (e) => C.submit(e, confirmCode));
  }

  async function signIn(fd) {
    try {
      const r = await C.api("/auth/login", {
        body: { identifier: fd.get("identifier"), password: fd.get("password"), deviceId: C.deviceId() },
        noRefresh: true,
      });
      if (r.status === "verify_device") {
        step = { kind: "device", challengeId: r.challengeId };
        askForCode(`This is a new device. We sent a code to ${r.maskedEmail}.`);
        return "";
      }
      C.setToken(r.accessToken);
      showConsent();
      return "";
    } catch (err) {
      if (err.status === 403 && err.data.status === "verify_email") {
        step = { kind: "verify", curieId: err.data.curieId };
        askForCode(`Confirm your email first. Enter the code sent to ${err.data.maskedEmail}.`);
        return "";
      }
      throw err;
    }
  }

  function askForCode(text) {
    document.getElementById("signin").hidden = true;
    document.getElementById("code").hidden = false;
    document.getElementById("code-text").textContent = text;
  }

  async function confirmCode(fd) {
    const r = step.kind === "device"
      ? await C.api("/auth/verify-device", {
          body: { challengeId: step.challengeId, code: fd.get("code"), deviceId: C.deviceId() },
          noRefresh: true,
        })
      : await C.api("/auth/verify-email", {
          body: { curieId: step.curieId, code: fd.get("code"), deviceId: C.deviceId() },
          noRefresh: true,
        });
    C.setToken(r.accessToken);
    showConsent();
    return "";
  }

  function showConsent() {
    const host = new URL(req.redirectUri).host;
    app.innerHTML = `
      <section class="card">
        <h1>${C.esc(appName)} wants to sign you in</h1>
        <p>It will receive your Curie ID, your name and your username. It won't receive your password, email, date of birth or gender.</p>
        <p class="muted">After you allow, you'll return to <strong>${C.esc(host)}</strong>.</p>
        <div class="actions">
          <button id="allow">Allow</button>
          <button id="deny" class="ghost">Cancel</button>
        </div>
        <p class="status" role="status"></p>
      </section>`;

    document.getElementById("deny").addEventListener("click", () => {
      // No redirect on cancel: we don't send anyone to an address we haven't checked.
      app.innerHTML = `<section class="card"><h1>Cancelled</h1><p>You can close this window and go back to ${C.esc(appName)}.</p></section>`;
    });

    document.getElementById("allow").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      const status = document.querySelector(".status");
      btn.disabled = true;
      try {
        const r = await C.api("/oauth/authorize-code", {
          body: {
            clientId: req.clientId,
            redirectUri: req.redirectUri,
            codeChallenge: req.codeChallenge,
            codeChallengeMethod: req.codeChallengeMethod,
            state: req.state,
          },
        });
        location.replace(r.redirect);
      } catch (err) {
        if (err.status === 401) { C.clearToken(); return start(); }
        btn.disabled = false;
        status.textContent = err.message;
        status.className = "status bad";
      }
    });
  }

  function showError(message) {
    app.innerHTML = `<section class="card"><h1>Can't continue</h1><p class="status bad">${C.esc(message)}</p></section>`;
  }
})();
