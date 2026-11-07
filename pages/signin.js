(function () {
  const C = window.Curie;
  let step = null;          // { kind: "device", challengeId } or { kind: "verify", curieId }
  let lastIdentifier = "";

  function show(id) {
    for (const f of ["signin", "code", "forgot", "reset"]) document.getElementById(f).hidden = f !== id;
  }

  document.getElementById("signin").addEventListener("submit", (e) => C.submit(e, async (fd) => {
    lastIdentifier = fd.get("identifier");
    try {
      const r = await C.api("/auth/login", {
        body: { identifier: lastIdentifier, password: fd.get("password"), deviceId: C.deviceId() },
        noRefresh: true,
      });
      if (r.status === "verify_device") {
        step = { kind: "device", challengeId: r.challengeId };
        document.getElementById("code-text").textContent =
          `This is a new device. We sent a code to ${r.maskedEmail}.`;
        show("code");
        return "";
      }
      C.setToken(r.accessToken);
      location.href = "account.html";
      return "";
    } catch (err) {
      if (err.status === 403 && err.data.status === "verify_email") {
        step = { kind: "verify", curieId: err.data.curieId };
        document.getElementById("code-text").textContent =
          `Confirm your email first. Enter the code sent to ${err.data.maskedEmail}, or ask for a new one.`;
        show("code");
        return "";
      }
      throw err;
    }
  }));

  document.getElementById("code").addEventListener("submit", (e) => C.submit(e, async (fd) => {
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
    location.href = "account.html";
    return "";
  }));

  document.getElementById("code-cancel").addEventListener("click", () => show("signin"));
  document.getElementById("forgot-open").addEventListener("click", () => show("forgot"));

  document.getElementById("forgot").addEventListener("submit", (e) => C.submit(e, async (fd) => {
    lastIdentifier = fd.get("identifier");
    await C.api("/auth/forgot", { body: { identifier: lastIdentifier }, noRefresh: true });
    show("reset");
    return "";
  }));

  document.getElementById("reset").addEventListener("submit", (e) => C.submit(e, async (fd) => {
    const code = fd.get("code") || "";
    const backupCode = fd.get("backupCode") || "";
    if (!code && !backupCode) throw new Error("Enter the code from your email, or a backup code.");
    await C.api("/auth/reset", {
      body: { identifier: lastIdentifier, code, backupCode, newPassword: fd.get("newPassword") },
      noRefresh: true,
    });
    show("signin");
    return "Password updated. Sign in with it.";
  }));
})();
