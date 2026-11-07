/* Example app: the whole Sign in with Curie ID flow in one page. Copy it as a starting point. */
(function () {
  const CLIENT_ID = "curie-example";                  // the client ID registered in APPS_JSON
  const API = (window.CURIE_API || "").replace(/\/$/, "");
  const REDIRECT = location.origin + location.pathname; // must match a registered redirect address exactly
  const out = document.getElementById("out");

  const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const random = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));
  const sha256 = async (text) => b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));

  // Step 1: make a secret verifier, send the user to Curie ID with its hash (the challenge).
  async function start() {
    const verifier = random(48);
    const state = random(16);
    sessionStorage.setItem("curieExample", JSON.stringify({ verifier, state }));
    const url = new URL(location.origin + "/authorize.html");
    url.search = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_challenge: await sha256(verifier),
      code_challenge_method: "S256",
      state,
    }).toString();
    location.href = url.toString();
  }

  // Step 2: Curie ID sends the user back with a code. Exchange it for a token, then ask who the user is.
  async function finish(code, state) {
    const saved = JSON.parse(sessionStorage.getItem("curieExample") || "null");
    if (!saved || saved.state !== state) {
      throw new Error("This sign-in didn't start from this app, so it was stopped. Please try again.");
    }
    const tokenRes = await fetch(API + "/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        client_id: CLIENT_ID,
        code_verifier: saved.verifier,
      }),
    });
    const token = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(token.error_description || "Sign-in failed.");
    sessionStorage.removeItem("curieExample");

    const meRes = await fetch(API + "/oauth/userinfo", {
      headers: { Authorization: "Bearer " + token.access_token },
    });
    const me = await meRes.json();
    if (!meRes.ok) throw new Error(me.error || "Could not read the account.");
    out.innerHTML = `
      <h2>Signed in</h2>
      <p>Name: <strong>${esc(me.name)}</strong></p>
      <p>Username: <strong>${esc(me.preferred_username || "not set")}</strong></p>
      <p>Curie ID: <strong>${esc(me.sub)}</strong></p>`;
  }

  const params = new URLSearchParams(location.search);
  if (params.get("error")) {
    out.textContent = "Sign-in was cancelled.";
  } else if (params.get("code")) {
    finish(params.get("code"), params.get("state") || "").catch((e) => { out.textContent = e.message; });
  } else {
    document.getElementById("start").addEventListener("click", start);
  }
})();
