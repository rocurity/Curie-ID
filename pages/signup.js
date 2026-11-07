(function () {
  const C = window.Curie;
  let pending = null; // { curieId }

  document.getElementById("signup").addEventListener("submit", (e) => C.submit(e, async (fd) => {
    if (fd.get("password") !== fd.get("confirm")) throw new Error("The two passwords don't match.");
    const r = await C.api("/auth/register", {
      body: {
        displayName: fd.get("displayName"),
        username: fd.get("username"),
        email: fd.get("email"),
        dateOfBirth: fd.get("dateOfBirth"),
        gender: fd.get("gender") || null,
        password: fd.get("password"),
        deviceId: C.deviceId(),
      },
    });
    pending = { curieId: r.curieId };
    e.target.hidden = true;
    document.getElementById("verify").hidden = false;
    document.getElementById("sent").textContent =
      `We sent a code to ${r.maskedEmail}. Your Curie ID is ${r.curieId}.`;
    return "";
  }));

  document.getElementById("verify").addEventListener("submit", (e) => C.submit(e, async (fd) => {
    const r = await C.api("/auth/verify-email", {
      body: { curieId: pending.curieId, code: fd.get("code"), deviceId: C.deviceId() },
      noRefresh: true,
    });
    C.setToken(r.accessToken);
    showDone(r);
    return "";
  }));

  // Shown once: the backup codes can't be retrieved later.
  function showDone(r) {
    document.getElementById("verify").hidden = true;
    const box = document.getElementById("done");
    box.hidden = false;
    box.innerHTML = `
      <h2>Your account is ready</h2>
      <p>Your Curie ID: <strong>${C.esc(r.curieId)}</strong></p>
      <p><strong>Save these backup codes now.</strong> Each one resets your password once, even if you can't get email. They won't be shown again.</p>
      <pre>${r.backupCodes.map((c) => C.esc(c)).join("\n")}</pre>
      <button id="continue">I've saved them. Go to my account</button>`;
    document.getElementById("continue").addEventListener("click", () => { location.href = "account.html"; });
  }

  document.getElementById("resend").addEventListener("click", async () => {
    const status = document.querySelector("#verify .status");
    try {
      await C.api("/auth/resend-email", { body: { curieId: pending.curieId }, noRefresh: true });
      status.textContent = "We sent a new code.";
    } catch (err) {
      status.textContent = err.message;
    }
  });
})();
