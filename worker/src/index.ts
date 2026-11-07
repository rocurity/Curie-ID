/**
 * Curie ID — Cloudflare Workers backend (free plan).
 * Storage: D1. Email: Brevo. Passwords: PBKDF2-SHA256 (Web Crypto, no npm deps).
 * Tokens: HS256 JWT signed with JWT_SECRET. Codes are HMAC'd with CODE_SECRET.
 * Sessions live in D1 and are checked on every request.
 */

export interface Env {
  DB: D1Database;
  JWT_SECRET: string;
  CODE_SECRET: string;
  BREVO_API_KEY: string;
  MAIL_FROM_EMAIL: string;
  MAIL_FROM_NAME: string;
  PBKDF2_ITERATIONS: string;
  MIN_AGE: string;
  ALLOWED_ORIGIN: string;
  ADMIN_TOKEN?: string;
}

class HttpError extends Error {
  constructor(public status: number, message: string, public extra?: Record<string, unknown>) {
    super(message);
  }
}

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const TOKEN_TTL_MS = HOUR;               // access token
const SESSION_TTL_MS = 30 * DAY;         // session
const CODE_TTL_MS = 10 * MINUTE;         // emailed codes
const CODE_MAX_ATTEMPTS = 5;
const PENDING_TTL_MS = 30 * MINUTE;      // unconfirmed sign-ups are removed after this
const MAX_PASSWORD = 128;
const MAX_BODY = 16_384;

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CURIE_RE = /^\d{12}c$/;
const GENDERS = ["male", "female", "other", "prefer_not_to_say"];
const WRONG_CODE = "That code isn't right, or it has expired. Ask for a new one if needed.";

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(s: string): Uint8Array {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function randomId(n = 18): string {
  return b64url(randomBytes(n));
}

/** Uniform random digits: 64 random bits reduced modulo 10^n (bias is negligible). */
function randomDigits(n: number): string {
  let v = 0n;
  for (const x of randomBytes(8)) v = (v << 8n) | BigInt(x);
  return (v % 10n ** BigInt(n)).toString().padStart(n, "0");
}

function newCurieId(): string {
  return `${randomDigits(12)}c`;
}

function constantTimeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const hmacKeys = new Map<string, CryptoKey>();
async function hmacKey(secret: string): Promise<CryptoKey> {
  let key = hmacKeys.get(secret);
  if (!key) {
    key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);
    hmacKeys.set(secret, key);
  }
  return key;
}

async function hmacHex(secret: string, value: string): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(value));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
  return new Uint8Array(bits);
}

// Format: pbkdf2_sha256$<iterations>$<salt>$<hash>. The iteration count is stored with each
// hash, so PBKDF2_ITERATIONS can be raised later without breaking existing logins.
async function hashPassword(env: Env, password: string): Promise<string> {
  const iterations = Number(env.PBKDF2_ITERATIONS) || 100000;
  const salt = randomBytes(16);
  const hash = await pbkdf2(password, salt, iterations);
  return `pbkdf2_sha256$${iterations}$${b64url(salt)}$${b64url(hash)}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [alg, iter, saltB64, hashB64] = stored.split("$");
  if (alg !== "pbkdf2_sha256" || !iter || !saltB64 || !hashB64) return false;
  const actual = await pbkdf2(password, unb64url(saltB64), Number(iter));
  return constantTimeEqualBytes(actual, unb64url(hashB64));
}

// A real hash computed once per isolate. Running it on unknown identifiers makes a
// missing account take as long as a wrong password, so timing can't reveal accounts.
let dummyHashPromise: Promise<string> | null = null;
function dummyHash(env: Env): Promise<string> {
  if (!dummyHashPromise) dummyHashPromise = hashPassword(env, randomId(24));
  return dummyHashPromise;
}

async function signToken(env: Env, payload: Record<string, unknown>): Promise<string> {
  const header = b64url(enc.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const data = `${header}.${body}`;
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env.JWT_SECRET), enc.encode(data));
  return `${data}.${b64url(new Uint8Array(sig))}`;
}

/** Verifies signature and claims. With checkExpiry false, an expired token still counts. */
async function readToken(env: Env, token: string, checkExpiry: boolean): Promise<Record<string, any>> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new HttpError(401, "Sign in again");
  const [h, p, s] = parts;
  try {
    const header = JSON.parse(dec.decode(unb64url(h)));
    if (header.alg !== "HS256") throw new Error("alg");
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(env.JWT_SECRET), unb64url(s), enc.encode(`${h}.${p}`));
    if (!ok) throw new Error("signature");
    const claims = JSON.parse(dec.decode(unb64url(p)));
    if (claims.iss !== "curie-id" || claims.aud !== "curie-apps" || !claims.sub || !claims.sid) {
      throw new Error("claims");
    }
    if (checkExpiry && claims.exp * 1000 < Date.now()) throw new Error("expired");
    return claims;
  } catch {
    throw new HttpError(401, "Sign in again");
  }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

async function readJson(req: Request): Promise<Record<string, any>> {
  const text = await req.text();
  if (text.length > MAX_BODY) throw new HttpError(413, "Request too large.");
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new HttpError(400, "Send the request as JSON.");
  }
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, any>) : {};
}

function cleanStr(v: unknown, max: number): string {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    throw new HttpError(400, "Bad id in the address.");
  }
}

function maskEmail(email: string): string {
  const [user, domain] = email.split("@");
  return `${user.slice(0, 1)}***@${domain}`;
}

function isUniqueError(e: unknown): boolean {
  return e instanceof Error && /UNIQUE constraint failed/i.test(e.message);
}

function validatePassword(p: unknown): string | null {
  if (typeof p !== "string" || p.length < 8 || p.length > MAX_PASSWORD) {
    return "Password needs 8 to 128 characters.";
  }
  if (!/[a-zA-Z]/.test(p) || !/[0-9]/.test(p)) return "Password needs letters and numbers.";
  return null;
}

/** Whole years of age, or null if the date isn't a real past date. */
function ageFrom(dob: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dob);
  if (!m) return null;
  const y = Number(m[1]), mo = Number(m[2]), d = Number(m[3]);
  const birth = new Date(Date.UTC(y, mo - 1, d));
  if (birth.getUTCFullYear() !== y || birth.getUTCMonth() !== mo - 1 || birth.getUTCDate() !== d) return null;
  if (birth.getTime() > Date.now()) return null;
  const now = new Date();
  let age = now.getUTCFullYear() - y;
  const beforeBirthday = now.getUTCMonth() < mo - 1 || (now.getUTCMonth() === mo - 1 && now.getUTCDate() < d);
  if (beforeBirthday) age--;
  return age;
}

/**
 * One atomic statement: counts this attempt in the current window and returns true
 * when the count is over `max`. Nothing is read first, so concurrent requests can't
 * slip past the limit. Every call counts as an attempt.
 */
async function rateLimited(env: Env, key: string, max: number, windowMs: number): Promise<boolean> {
  const now = Date.now();
  const cutoff = now - windowMs;
  const row = await env.DB.prepare(
    "INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1) " +
      "ON CONFLICT(key) DO UPDATE SET " +
      "count = CASE WHEN rate_limits.window_start < ? THEN 1 ELSE rate_limits.count + 1 END, " +
      "window_start = CASE WHEN rate_limits.window_start < ? THEN ? ELSE rate_limits.window_start END " +
      "RETURNING count",
  ).bind(key, now, cutoff, cutoff, now).first<{ count: number }>();
  return !row || row.count > max;
}

async function logEvent(env: Env, curieId: string, type: string): Promise<void> {
  await env.DB.prepare("INSERT INTO events (curie_id, type, created_at) VALUES (?, ?, ?)")
    .bind(curieId, type, Date.now())
    .run();
}

async function sendEmail(env: Env, to: string, subject: string, text: string, html: string): Promise<void> {
  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      sender: { name: env.MAIL_FROM_NAME, email: env.MAIL_FROM_EMAIL },
      to: [{ email: to }],
      subject,
      textContent: text,
      htmlContent: html,
    }),
  });
  if (!res.ok) {
    console.error("Brevo error", res.status, await res.text());
    throw new HttpError(502, "We couldn't send the email. Try again in a few minutes.");
  }
}

function escHtml(s: string): string {
  const map: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return s.replace(/[&<>"']/g, (c) => map[c]);
}

/** Large, high-contrast email: the Curie ID and the code are impossible to miss. */
function emailHtml(o: { heading: string; body: string; curieId?: string; code?: string; footer: string }): string {
  const box = (label: string, value: string, size: number, spacing: number, colour: string) =>
    `<div style="margin:24px 0;padding:24px;background:#f4efe6;border:3px solid #2d5b4e;border-radius:12px;text-align:center">` +
    `<div style="font-size:16px;font-weight:bold;color:#6b645a;letter-spacing:1px">${label}</div>` +
    `<div style="font-size:${size}px;font-weight:bold;letter-spacing:${spacing}px;color:${colour};margin-top:10px">${escHtml(value)}</div></div>`;
  return (
    `<!doctype html><html><body style="margin:0;padding:12px;background:#f4efe6;font-family:Arial,Helvetica,sans-serif;color:#1c1a17">` +
    `<div style="max-width:580px;margin:0 auto;background:#ffffff;border-radius:14px;padding:20px">` +
    `<div style="font-size:18px;font-weight:bold;letter-spacing:3px;color:#2d5b4e">CURIE ID</div>` +
    `<h1 style="font-size:34px;line-height:1.2;margin:14px 0 16px;font-weight:bold">${escHtml(o.heading)}</h1>` +
    `<p style="font-size:20px;line-height:1.5;margin:0;font-weight:bold">${escHtml(o.body)}</p>` +
    (o.curieId ? box("YOUR CURIE ID", o.curieId, 30, 3, "#1c1a17") : "") +
    (o.code ? `<p style="font-size:20px;font-weight:bold;margin:24px 0 0">Your code:</p><div style="margin:8px 0 24px;padding:18px 8px;background:#f4efe6;border:3px solid #2d5b4e;border-radius:12px;text-align:center"><span style="font-size:40px;font-weight:bold;letter-spacing:2px;color:#2d5b4e;white-space:nowrap">${escHtml(o.code)}</span></div>` : "") +
    `<p style="font-size:18px;line-height:1.5;margin:24px 0 0"><strong>This code expires in 10 minutes.</strong> ${escHtml(o.footer)}</p>` +
    `</div></body></html>`
  );
}

/** Creates a 6-digit code, stores only its HMAC, and emails it. */
async function issueCode(
  env: Env,
  o: { id: string; curieId: string; purpose: string; deviceId: string | null; to: string; subject: string; heading: string; intro: string; footer: string; showId: boolean },
): Promise<void> {
  const existing = await env.DB.prepare("SELECT created_at FROM codes WHERE id = ?")
    .bind(o.id).first<{ created_at: number }>();
  if (existing && Date.now() - existing.created_at < MINUTE) {
    throw new HttpError(429, "Please wait a minute before asking for another code.");
  }
  const code = randomDigits(6);
  const codeHash = await hmacHex(env.CODE_SECRET, `${o.id}:${code}`);
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO codes (id, curie_id, purpose, device_id, code_hash, attempts, created_at, expires_at) " +
      "VALUES (?, ?, ?, ?, ?, 0, ?, ?) " +
      "ON CONFLICT(id) DO UPDATE SET code_hash = excluded.code_hash, attempts = 0, " +
      "created_at = excluded.created_at, expires_at = excluded.expires_at",
  ).bind(o.id, o.curieId, o.purpose, o.deviceId, codeHash, now, now + CODE_TTL_MS).run();
  const text = `${o.heading}\n\n${o.intro}\n\n${o.showId ? `Your Curie ID: ${o.curieId}\n` : ""}Your code: ${code}\n\nIt expires in 10 minutes. ${o.footer}`;
  const html = emailHtml({
    heading: o.heading,
    body: o.intro,
    curieId: o.showId ? o.curieId : undefined,
    code,
    footer: o.footer,
  });
  await sendEmail(env, o.to, o.subject, text, html);
}

/**
 * Checks and uses a code in two atomic steps:
 * 1. Count the attempt and fetch the row, only if it's unexpired and under the attempt limit.
 * 2. On a correct code, delete the row only if its hash still matches. If two correct
 *    submissions race, only one delete succeeds, so the code works exactly once.
 * Wrong guesses still count, so brute force stays capped at CODE_MAX_ATTEMPTS.
 */
async function redeemCode(env: Env, id: string, code: unknown, deviceId?: string): Promise<Record<string, any>> {
  const row = await env.DB.prepare(
    "UPDATE codes SET attempts = attempts + 1 WHERE id = ? AND expires_at > ? AND attempts < ? " +
      "RETURNING id, curie_id, purpose, device_id, code_hash",
  ).bind(id, Date.now(), CODE_MAX_ATTEMPTS).first<Record<string, any>>();
  if (!row) throw new HttpError(400, WRONG_CODE);

  const deviceOk = !row.device_id || row.device_id === deviceId;
  const expected = await hmacHex(env.CODE_SECRET, `${id}:${String(code ?? "").trim()}`);
  if (!deviceOk || !constantTimeEqualStr(expected, row.code_hash)) throw new HttpError(400, WRONG_CODE);

  const used = await env.DB.prepare("DELETE FROM codes WHERE id = ? AND code_hash = ?")
    .bind(id, row.code_hash).run();
  if (!used.meta.changes) throw new HttpError(400, WRONG_CODE); // another request just used it
  return row;
}

async function trustDevice(env: Env, curieId: string, deviceId: string): Promise<void> {
  await env.DB.prepare("INSERT OR IGNORE INTO devices (curie_id, device_id, added_at) VALUES (?, ?, ?)")
    .bind(curieId, deviceId, Date.now()).run();
}

async function tokenFor(env: Env, curieId: string, sid: string) {
  const now = Math.floor(Date.now() / 1000);
  const accessToken = await signToken(env, {
    iss: "curie-id",
    aud: "curie-apps",
    sub: curieId,
    sid,
    iat: now,
    exp: now + TOKEN_TTL_MS / 1000,
  });
  return { accessToken, tokenType: "Bearer", expiresIn: TOKEN_TTL_MS / 1000, curieId };
}

async function createSession(env: Env, curieId: string, deviceId: string | null) {
  const sid = randomId(18);
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO sessions (sid, curie_id, device_id, created_at, last_used_at, expires_at, revoked) " +
      "VALUES (?, ?, ?, ?, ?, ?, 0)",
  ).bind(sid, curieId, deviceId, now, now, now + SESSION_TTL_MS).run();
  return tokenFor(env, curieId, sid);
}

/** Checks the bearer token and its session row. Returns the signed-in user. */
async function authenticate(env: Env, req: Request): Promise<{ curieId: string; sid: string }> {
  const header = req.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) throw new HttpError(401, "Sign in again");
  const claims = await readToken(env, header.slice(7), true);
  const row = await env.DB.prepare(
    "SELECT s.curie_id, s.revoked, s.expires_at, u.status FROM sessions s " +
      "JOIN users u ON u.curie_id = s.curie_id WHERE s.sid = ?",
  ).bind(claims.sid).first<Record<string, any>>();
  if (!row || row.revoked || row.expires_at < Date.now() || row.curie_id !== claims.sub) {
    throw new HttpError(401, "Sign in again");
  }
  if (row.status !== "active") throw new HttpError(403, "This account can't be used right now.");
  return { curieId: claims.sub, sid: claims.sid };
}

async function findAccount(env: Env, raw: unknown): Promise<Record<string, any> | null> {
  const v = cleanStr(raw, 254).toLowerCase();
  if (!v) return null;
  if (CURIE_RE.test(v)) return env.DB.prepare("SELECT * FROM users WHERE curie_id = ?").bind(v).first();
  if (EMAIL_RE.test(v)) return env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(v).first();
  if (USERNAME_RE.test(v)) return env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(v).first();
  return null;
}

// ---------------------------------------------------------------------------
// Sign-up, confirmation and sign-in
// ---------------------------------------------------------------------------

async function register(env: Env, req: Request, ip: string): Promise<Response> {
  const b = await readJson(req);
  const displayName = cleanStr(b.displayName, 60);
  const username = cleanStr(b.username, 20).toLowerCase();
  const email = cleanStr(b.email, 254).toLowerCase();
  const dob = cleanStr(b.dateOfBirth, 10);
  const gender = b.gender ? String(b.gender) : null;
  const deviceId = cleanStr(b.deviceId, 100);

  if (!displayName) throw new HttpError(400, "Enter your name.");
  if (!USERNAME_RE.test(username)) {
    throw new HttpError(400, "Username: 3–20 characters, lowercase letters, numbers and underscores.");
  }
  if (!EMAIL_RE.test(email)) throw new HttpError(400, "Enter a valid email address.");
  const age = ageFrom(dob);
  if (age === null || age > 120) throw new HttpError(400, "Enter a valid date of birth.");
  const minAge = Number(env.MIN_AGE) || 13;
  if (age < minAge) throw new HttpError(400, `You must be at least ${minAge} to create a Curie ID.`);
  if (gender && !GENDERS.includes(gender)) throw new HttpError(400, "Choose a gender option or leave it blank.");
  const pwError = validatePassword(b.password);
  if (pwError) throw new HttpError(400, pwError);
  if (!deviceId) throw new HttpError(400, "Missing device.");
  if (await rateLimited(env, `register:${ip}`, 10, HOUR)) {
    throw new HttpError(429, "Too many sign-ups from this network. Try again later.");
  }

  // Free up unconfirmed sign-ups so their username and email can be reused.
  await env.DB.prepare("DELETE FROM users WHERE status = 'pending_email' AND created_at < ?")
    .bind(Date.now() - PENDING_TTL_MS).run();

  const passwordHash = await hashPassword(env, b.password);
  let curieId = "";
  for (let attempt = 0; attempt < 5 && !curieId; attempt++) {
    const candidate = newCurieId();
    try {
      await env.DB.prepare(
        "INSERT INTO users (curie_id, username, email, display_name, date_of_birth, gender, " +
          "password_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_email', ?)",
      ).bind(candidate, username, email, displayName, dob, gender, passwordHash, Date.now()).run();
      curieId = candidate;
    } catch (e) {
      if (!isUniqueError(e)) throw e;
      const taken = await env.DB.prepare("SELECT username, email FROM users WHERE username = ? OR email = ?")
        .bind(username, email).all<{ username: string; email: string }>();
      if (taken.results.some((r) => r.username === username)) throw new HttpError(409, "That username is taken.");
      if (taken.results.some((r) => r.email === email)) {
        // Deliberate trade-off: this tells people an email is registered, so sign-up is usable.
        throw new HttpError(409, "That email already has a Curie ID. Sign in or reset your password.");
      }
      // Otherwise it was a Curie ID collision; try another number.
    }
  }
  if (!curieId) throw new HttpError(500, "Could not create your account. Try again.");

  try {
    await issueCode(env, {
      id: `${curieId}:verify`,
      curieId,
      purpose: "verify",
      deviceId: null,
      to: email,
      subject: "Confirm your Curie ID",
      heading: `Welcome to Curie ID, ${displayName}!`,
      intro: "Use this code to confirm your email and finish creating your account.",
      showId: false,
      footer: "If you didn't create a Curie ID, you can ignore this email.",
    });
  } catch (e) {
    await env.DB.prepare("DELETE FROM users WHERE curie_id = ?").bind(curieId).run();
    throw e;
  }
  return json({ status: "verify_email", curieId, maskedEmail: maskEmail(email) }, 201);
}

async function resendEmail(env: Env, req: Request, ip: string): Promise<Response> {
  const b = await readJson(req);
  const curieId = cleanStr(b.curieId, 13).toLowerCase();
  if (!CURIE_RE.test(curieId)) throw new HttpError(400, "Enter a valid Curie ID.");
  if (await rateLimited(env, `resend-ip:${ip}`, 10, HOUR)) throw new HttpError(429, "Too many requests. Try again later.");
  if (await rateLimited(env, `resend-acct:${curieId}`, 5, HOUR)) throw new HttpError(429, "Too many requests. Try again later.");
  const user = await env.DB.prepare("SELECT * FROM users WHERE curie_id = ?").bind(curieId).first<Record<string, any>>();
  if (user && user.status === "pending_email") {
    await issueCode(env, {
      id: `${curieId}:verify`,
      curieId,
      purpose: "verify",
      deviceId: null,
      to: user.email,
      subject: "Confirm your Curie ID",
      heading: "Confirm your email",
      intro: "Use this code to finish creating your Curie ID.",
      showId: false,
      footer: "If you didn't ask for this, ignore this email.",
    });
  }
  return json({ ok: true });
}

async function verifyEmail(env: Env, req: Request): Promise<Response> {
  const b = await readJson(req);
  const curieId = cleanStr(b.curieId, 13).toLowerCase();
  const deviceId = cleanStr(b.deviceId, 100);
  if (!CURIE_RE.test(curieId) || !deviceId) throw new HttpError(400, WRONG_CODE);
  const user = await env.DB.prepare("SELECT * FROM users WHERE curie_id = ?").bind(curieId).first<Record<string, any>>();
  if (!user || user.status !== "pending_email") throw new HttpError(400, WRONG_CODE);

  await redeemCode(env, `${curieId}:verify`, b.code);
  await env.DB.prepare("UPDATE users SET status = 'active' WHERE curie_id = ?").bind(curieId).run();
  await trustDevice(env, curieId, deviceId);
  await logEvent(env, curieId, "account_created");
  const backupCodes = await createBackupCodes(env, curieId);
  return json({ ...(await createSession(env, curieId, deviceId)), backupCodes }, 201);
}

async function login(env: Env, req: Request, ip: string): Promise<Response> {
  const b = await readJson(req);
  const identifier = cleanStr(b.identifier, 254);
  const password = typeof b.password === "string" ? b.password : "";
  const deviceId = cleanStr(b.deviceId, 100);
  if (!identifier || !password || !deviceId) throw new HttpError(400, "Enter your details.");

  // Limits are keyed by the identifier typed and the IP. Locking an account would let
  // anyone lock out its owner, so the limit only blocks the guessing source.
  const ident = identifier.toLowerCase();
  if (await rateLimited(env, `login-ip:${ip}`, 50, 15 * MINUTE)) {
    throw new HttpError(429, "Too many attempts from this network. Try again later.");
  }
  if (await rateLimited(env, `login:${ident}:${ip}`, 5, 15 * MINUTE)) {
    throw new HttpError(429, "Too many attempts. Try again in 15 minutes.");
  }

  const badLogin = () => new HttpError(401, "Wrong Curie ID, username, email or password.");
  // Length check first; it doesn't depend on whether the account exists.
  if (password.length > MAX_PASSWORD) throw badLogin();

  // Always run one hash, so a missing account costs the same time as a wrong password.
  const user = await findAccount(env, identifier);
  const ok = await verifyPassword(password, user?.password_hash ?? (await dummyHash(env)));
  if (!user || !ok) throw badLogin();

  const maskedEmail = maskEmail(user.email);
  if (user.status === "pending_email") {
    throw new HttpError(403, "Confirm your email first.", { status: "verify_email", curieId: user.curie_id, maskedEmail });
  }
  if (user.status !== "active") throw new HttpError(403, "This account can't be used right now.");

  const trusted = await env.DB.prepare("SELECT 1 AS found FROM devices WHERE curie_id = ? AND device_id = ?")
    .bind(user.curie_id, deviceId).first();
  if (trusted) {
    await logEvent(env, user.curie_id, "login_success");
    return json(await createSession(env, user.curie_id, deviceId));
  }

  // A new device must confirm with a code sent to the account's email.
  if (await rateLimited(env, `device:${user.curie_id}`, 5, HOUR)) {
    throw new HttpError(429, "Too many sign-in attempts from new devices. Try again later.");
  }
  const challengeId = `dev_${randomId(18)}`;
  await issueCode(env, {
    id: challengeId,
    curieId: user.curie_id,
    purpose: "device",
    deviceId,
    to: user.email,
    subject: "New sign-in to your Curie ID",
    heading: "New sign-in to your account",
    intro: "Someone is signing in to your Curie ID from a new device. If this was you, enter the code below.",
    showId: false,
    footer: "If this wasn't you, change your password right away.",
  });
  return json({ status: "verify_device", challengeId, maskedEmail });
}

async function verifyDevice(env: Env, req: Request): Promise<Response> {
  const b = await readJson(req);
  const challengeId = cleanStr(b.challengeId, 80);
  const deviceId = cleanStr(b.deviceId, 100);
  if (!challengeId || !deviceId) throw new HttpError(400, WRONG_CODE);
  const row = await redeemCode(env, challengeId, b.code, deviceId);
  if (row.purpose !== "device") throw new HttpError(400, WRONG_CODE);

  // The account may have been suspended since the code was sent.
  const u = await env.DB.prepare("SELECT status FROM users WHERE curie_id = ?")
    .bind(row.curie_id).first<{ status: string }>();
  if (!u || u.status !== "active") throw new HttpError(403, "This account can't be used right now.");

  await trustDevice(env, row.curie_id, deviceId);
  await logEvent(env, row.curie_id, "device_added");
  return json(await createSession(env, row.curie_id, deviceId));
}

async function sendResetCode(env: Env, user: Record<string, any>): Promise<void> {
  try {
    if (await rateLimited(env, `forgot-acct:${user.curie_id}`, 3, HOUR)) return;
    await issueCode(env, {
      id: `${user.curie_id}:reset`,
      curieId: user.curie_id,
      purpose: "reset",
      deviceId: null,
      to: user.email,
      subject: "Reset your Curie ID password",
      heading: "Reset your password",
      intro: "Use this code to reset your Curie ID password.",
      showId: false,
      footer: "If you didn't ask for this, ignore this email.",
    });
  } catch (e) {
    console.error("forgot: could not send code", e);
  }
}

async function forgot(env: Env, req: Request, ip: string, ctx: ExecutionContext): Promise<Response> {
  const b = await readJson(req);
  if (await rateLimited(env, `forgot-ip:${ip}`, 10, HOUR)) throw new HttpError(429, "Too many requests. Try again later.");
  const user = await findAccount(env, b.identifier);
  // The email is sent after the response, so an existing account and a missing one answer
  // at the same speed and reveal nothing.
  if (user && user.status === "active") ctx.waitUntil(sendResetCode(env, user));
  return json({ ok: true, message: "If an account matches, we sent a code to its email." });
}

async function resetPassword(env: Env, req: Request): Promise<Response> {
  const b = await readJson(req);
  const pwError = validatePassword(b.newPassword);
  if (pwError) throw new HttpError(400, pwError);
  const user = await findAccount(env, b.identifier);
  if (!user || user.status !== "active") throw new HttpError(400, WRONG_CODE);

  if (b.backupCode) await useBackupCode(env, user.curie_id, b.backupCode);
  else await redeemCode(env, `${user.curie_id}:reset`, b.code);
  const hash = await hashPassword(env, b.newPassword);
  await env.DB.prepare("UPDATE users SET password_hash = ? WHERE curie_id = ?").bind(hash, user.curie_id).run();
  await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE curie_id = ?").bind(user.curie_id).run();
  await logEvent(env, user.curie_id, "password_reset");
  return json({ ok: true });
}

async function refresh(env: Env, req: Request): Promise<Response> {
  const header = req.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) throw new HttpError(401, "Sign in again");
  // An expired token is accepted here, but its session row must still be live.
  const claims = await readToken(env, header.slice(7), false);
  const row = await env.DB.prepare("SELECT curie_id, revoked, expires_at, last_used_at FROM sessions WHERE sid = ?")
    .bind(claims.sid).first<Record<string, any>>();
  if (!row || row.revoked || row.expires_at < Date.now() || row.curie_id !== claims.sub) {
    throw new HttpError(401, "Sign in again");
  }
  if (Date.now() - row.last_used_at > HOUR) {
    await env.DB.prepare("UPDATE sessions SET last_used_at = ? WHERE sid = ?").bind(Date.now(), claims.sid).run();
  }
  return json(await tokenFor(env, claims.sub, claims.sid));
}

/** Works with an expired access token, so a logout always succeeds. */
async function logout(env: Env, req: Request): Promise<Response> {
  const header = req.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) throw new HttpError(401, "Sign in again");
  const claims = await readToken(env, header.slice(7), false);
  await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE sid = ? AND curie_id = ?")
    .bind(claims.sid, claims.sub).run();
  await logEvent(env, claims.sub, "logout");
  return json({ ok: true });
}

// ---------------------------------------------------------------------------
// Signed-in account routes
// ---------------------------------------------------------------------------

async function loadMe(env: Env, curieId: string): Promise<Response> {
  const u = await env.DB.prepare("SELECT * FROM users WHERE curie_id = ?").bind(curieId).first<Record<string, any>>();
  if (!u) throw new HttpError(404, "Account not found");
  return json({
    curieId: u.curie_id,
    displayName: u.display_name,
    username: u.username,
    email: u.email,
    dateOfBirth: u.date_of_birth,
    gender: u.gender,
    createdAt: u.created_at,
  });
}

async function getMe(env: Env, req: Request): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  return loadMe(env, curieId);
}

async function patchMe(env: Env, req: Request): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  const b = await readJson(req);
  if (b.displayName !== undefined) {
    const name = cleanStr(b.displayName, 60);
    if (!name) throw new HttpError(400, "Enter your name.");
    await env.DB.prepare("UPDATE users SET display_name = ? WHERE curie_id = ?").bind(name, curieId).run();
  }
  if (b.username !== undefined) {
    const username = cleanStr(b.username, 20).toLowerCase();
    if (!USERNAME_RE.test(username)) {
      throw new HttpError(400, "Username: 3–20 characters, lowercase letters, numbers and underscores.");
    }
    try {
      await env.DB.prepare("UPDATE users SET username = ? WHERE curie_id = ?").bind(username, curieId).run();
    } catch (e) {
      if (isUniqueError(e)) throw new HttpError(409, "That username is taken.");
      throw e;
    }
  }
  if (b.gender !== undefined) {
    const gender = b.gender ? String(b.gender) : null;
    if (gender && !GENDERS.includes(gender)) throw new HttpError(400, "Choose a gender option or leave it blank.");
    await env.DB.prepare("UPDATE users SET gender = ? WHERE curie_id = ?").bind(gender, curieId).run();
  }
  // Date of birth and email change through their own verified flows, not here.
  return loadMe(env, curieId);
}

async function changePassword(env: Env, req: Request): Promise<Response> {
  const { curieId, sid } = await authenticate(env, req);
  const b = await readJson(req);
  const u = await env.DB.prepare("SELECT password_hash FROM users WHERE curie_id = ?")
    .bind(curieId).first<{ password_hash: string }>();
  if (!u || typeof b.currentPassword !== "string" || !(await verifyPassword(b.currentPassword, u.password_hash))) {
    throw new HttpError(401, "Current password is incorrect.");
  }
  const pwError = validatePassword(b.newPassword);
  if (pwError) throw new HttpError(400, pwError);
  const hash = await hashPassword(env, b.newPassword);
  await env.DB.prepare("UPDATE users SET password_hash = ? WHERE curie_id = ?").bind(hash, curieId).run();
  const r = await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE curie_id = ? AND sid <> ?").bind(curieId, sid).run();
  await logEvent(env, curieId, "password_changed");
  return json({ ok: true, sessionsEnded: r.meta.changes ?? 0 });
}

async function listSessions(env: Env, req: Request): Promise<Response> {
  const { curieId, sid } = await authenticate(env, req);
  const rows = await env.DB.prepare(
    "SELECT sid, device_id, created_at, last_used_at FROM sessions " +
      "WHERE curie_id = ? AND revoked = 0 AND expires_at > ? ORDER BY last_used_at DESC",
  ).bind(curieId, Date.now()).all<Record<string, any>>();
  return json({
    sessions: rows.results.map((s) => ({
      sid: s.sid,
      deviceId: s.device_id,
      createdAt: s.created_at,
      lastUsedAt: s.last_used_at,
      isCurrent: s.sid === sid,
    })),
  });
}

async function revokeSession(env: Env, req: Request, targetSid: string): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  const r = await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE sid = ? AND curie_id = ?")
    .bind(targetSid, curieId).run();
  if (!r.meta.changes) throw new HttpError(404, "Session not found");
  await logEvent(env, curieId, "session_revoked");
  return json({ ok: true });
}

async function revokeOthers(env: Env, req: Request): Promise<Response> {
  const { curieId, sid } = await authenticate(env, req);
  const r = await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE curie_id = ? AND sid <> ?").bind(curieId, sid).run();
  await logEvent(env, curieId, "sessions_revoked_others");
  return json({ ok: true, signedOut: r.meta.changes ?? 0 });
}

async function listDevices(env: Env, req: Request): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  const rows = await env.DB.prepare("SELECT device_id, added_at FROM devices WHERE curie_id = ? ORDER BY added_at DESC")
    .bind(curieId).all<Record<string, any>>();
  return json({ devices: rows.results.map((d) => ({ deviceId: d.device_id, addedAt: d.added_at })) });
}

async function revokeDevice(env: Env, req: Request, deviceId: string): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  const r = await env.DB.prepare("DELETE FROM devices WHERE curie_id = ? AND device_id = ?").bind(curieId, deviceId).run();
  if (!r.meta.changes) throw new HttpError(404, "Device not found");
  await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE curie_id = ? AND device_id = ?").bind(curieId, deviceId).run();
  await logEvent(env, curieId, "device_removed");
  return json({ ok: true });
}

async function activity(env: Env, req: Request): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  const rows = await env.DB.prepare(
    "SELECT type, created_at FROM events WHERE curie_id = ? ORDER BY created_at DESC LIMIT 30",
  ).bind(curieId).all<Record<string, any>>();
  return json({ events: rows.results.map((e) => ({ type: e.type, createdAt: e.created_at })) });
}

async function publicUser(env: Env, curieId: string): Promise<Response> {
  const u = await env.DB.prepare("SELECT display_name, username, status FROM users WHERE curie_id = ?")
    .bind(curieId).first<Record<string, any>>();
  if (!u || u.status !== "active") throw new HttpError(404, "Not found");
  // Public fields only: no email, date of birth or gender.
  return json({ curieId, displayName: u.display_name, username: u.username });
}

/** Admin only: times one password hash on this runtime, to choose PBKDF2_ITERATIONS. */
async function hashTiming(env: Env, req: Request): Promise<Response> {
  const provided = req.headers.get("x-admin-token") ?? "";
  if (!env.ADMIN_TOKEN || !constantTimeEqualStr(provided, env.ADMIN_TOKEN)) throw new HttpError(404, "Not found");
  const start = Date.now();
  await hashPassword(env, "timing-test-1");
  return json({
    iterations: Number(env.PBKDF2_ITERATIONS) || 100000,
    wallClockMs: Date.now() - start,
    note: "Wall-clock time. Workers' limit applies to CPU time, which is at most this value.",
  });
}

// ---------------------------------------------------------------------------
// Routing, headers, scheduled cleanup
// ---------------------------------------------------------------------------

async function route(req: Request, env: Env, path: string, ip: string, ctx: ExecutionContext): Promise<Response> {
  const m = req.method;
  if (m === "GET" && path === "/health") return json({ ok: true });

  if (m === "POST" && path === "/auth/register") return register(env, req, ip);
  if (m === "POST" && path === "/auth/resend-email") return resendEmail(env, req, ip);
  if (m === "POST" && path === "/auth/verify-email") return verifyEmail(env, req);
  if (m === "POST" && path === "/auth/login") return login(env, req, ip);
  if (m === "POST" && path === "/auth/verify-device") return verifyDevice(env, req);
  if (m === "POST" && path === "/auth/forgot") return forgot(env, req, ip, ctx);
  if (m === "POST" && path === "/auth/reset") return resetPassword(env, req);
  if (m === "POST" && path === "/auth/refresh") return refresh(env, req);
  if (m === "POST" && path === "/auth/logout") return logout(env, req);

  if (m === "GET" && path === "/me") return getMe(env, req);
  if (m === "PATCH" && path === "/me") return patchMe(env, req);
  if (m === "POST" && path === "/me/password") return changePassword(env, req);
  if (m === "GET" && path === "/me/sessions") return listSessions(env, req);
  if (m === "POST" && path === "/me/sessions/revoke-others") return revokeOthers(env, req);
  const sessionMatch = path.match(/^\/me\/sessions\/([A-Za-z0-9_-]+)\/revoke$/);
  if (m === "POST" && sessionMatch) return revokeSession(env, req, sessionMatch[1]);
  if (m === "GET" && path === "/me/devices") return listDevices(env, req);
  const deviceMatch = path.match(/^\/me\/devices\/([^/]+)\/revoke$/);
  if (m === "POST" && deviceMatch) return revokeDevice(env, req, safeDecode(deviceMatch[1]));
  if (m === "GET" && path === "/me/activity") return activity(env, req);
  if (m === "GET" && path === "/me/security") return securityInfo(env, req);
  if (m === "POST" && path === "/me/sessions/revoke-all") return signOutEverywhere(env, req);
  if (m === "POST" && path === "/account/backup-codes") return newBackupCodes(env, req);

  const userMatch = path.match(/^\/user\/(\d{12}c)$/i);
  if (m === "GET" && userMatch) return publicUser(env, userMatch[1].toLowerCase());

  if (m === "GET" && path === "/admin/hash-timing") return hashTiming(env, req);

  return json({ error: "Not found" }, 404);
}

const ALNUM = "abcdefghjkmnpqrstuvwxyz23456789";
function randomCode(n: number): string {
  return Array.from(randomBytes(n), (b) => ALNUM[b % ALNUM.length]).join("");
}

async function hashBackupCode(env: Env, code: string): Promise<string> {
  return hmacHex(env.CODE_SECRET, "backup:" + code.toLowerCase().replace(/[^a-z0-9]/g, ""));
}

/** Makes 8 one-time backup codes, stores only their hashes, and returns the plain codes once. */
async function createBackupCodes(env: Env, curieId: string): Promise<string[]> {
  const codes = Array.from({ length: 8 }, () => `${randomCode(4)}-${randomCode(4)}`);
  const hashes = await Promise.all(codes.map((c) => hashBackupCode(env, c)));
  await env.DB.prepare("UPDATE users SET backup_codes = ? WHERE curie_id = ?")
    .bind(JSON.stringify(hashes), curieId).run();
  return codes;
}

/** Uses one backup code. The update only succeeds if the stored list is unchanged, so a code works once. */
async function useBackupCode(env: Env, curieId: string, code: unknown): Promise<void> {
  const row = await env.DB.prepare("SELECT backup_codes FROM users WHERE curie_id = ?")
    .bind(curieId).first<{ backup_codes: string | null }>();
  const list: string[] = row?.backup_codes ? JSON.parse(row.backup_codes) : [];
  const h = await hashBackupCode(env, String(code ?? ""));
  if (!list.includes(h)) throw new HttpError(400, WRONG_CODE);
  const r = await env.DB.prepare("UPDATE users SET backup_codes = ? WHERE curie_id = ? AND backup_codes IS ?")
    .bind(JSON.stringify(list.filter((x) => x !== h)), curieId, row?.backup_codes ?? null).run();
  if (!r.meta.changes) throw new HttpError(400, WRONG_CODE);
}

async function securityInfo(env: Env, req: Request): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  const row = await env.DB.prepare("SELECT backup_codes FROM users WHERE curie_id = ?")
    .bind(curieId).first<{ backup_codes: string | null }>();
  const left = row?.backup_codes ? (JSON.parse(row.backup_codes) as string[]).length : 0;
  return json({ backupCodesLeft: left });
}

/** Makes new backup codes, which replace the old ones. Requires the account password. */
async function newBackupCodes(env: Env, req: Request): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  const b = await readJson(req);
  if (await rateLimited(env, `backup:${curieId}`, 5, HOUR)) throw new HttpError(429, "Too many attempts. Try again later.");
  const u = await env.DB.prepare("SELECT password_hash FROM users WHERE curie_id = ?")
    .bind(curieId).first<{ password_hash: string }>();
  if (!u || typeof b.password !== "string" || !(await verifyPassword(b.password, u.password_hash))) {
    throw new HttpError(401, "Password is incorrect.");
  }
  const codes = await createBackupCodes(env, curieId);
  await logEvent(env, curieId, "backup_codes_regenerated");
  return json({ codes });
}

/** Ends every session, including the one making the request. */
async function signOutEverywhere(env: Env, req: Request): Promise<Response> {
  const { curieId } = await authenticate(env, req);
  const r = await env.DB.prepare("UPDATE sessions SET revoked = 1 WHERE curie_id = ?").bind(curieId).run();
  await logEvent(env, curieId, "sessions_revoked_all");
  return json({ ok: true, signedOut: r.meta.changes ?? 0 });
}

function withHeaders(env: Env, res: Response): Response {
  const headers = new Headers(res.headers);
  headers.set("Access-Control-Allow-Origin", env.ALLOWED_ORIGIN || "*");
  headers.set("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Admin-Token");
  headers.set("Access-Control-Max-Age", "86400");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Cache-Control", "no-store");
  return new Response(res.body, { status: res.status, headers });
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (req.method === "OPTIONS") return withHeaders(env, new Response(null, { status: 204 }));
    if (Number(req.headers.get("content-length") || 0) > MAX_BODY) {
      return withHeaders(env, json({ error: "Request too large." }, 413));
    }
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const ip = req.headers.get("cf-connecting-ip") || "unknown";
    let res: Response;
    try {
      res = await route(req, env, path, ip, ctx);
    } catch (err) {
      if (err instanceof HttpError) {
        res = json({ error: err.message, ...(err.extra || {}) }, err.status);
      } else {
        console.error("unhandled", err);
        res = json({ error: "Something went wrong. Try again." }, 500);
      }
    }
    return withHeaders(env, res);
  },

  /** Runs on the cron schedule in wrangler.toml to keep the free-plan tables small. */
  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    const now = Date.now();
    await env.DB.prepare("DELETE FROM events WHERE created_at < ?").bind(now - 90 * DAY).run();
    await env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - DAY).run();
    await env.DB.prepare("DELETE FROM codes WHERE expires_at < ?").bind(now).run();
    await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now).run();
  },
};
