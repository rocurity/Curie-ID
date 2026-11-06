# Curie ID — Cloudflare edition

Free-tier identity service: Cloudflare Workers (backend) + D1 (database) + Brevo (email), with your own sign-up, sign-in and password handling. No Firebase Auth.

## What it does

- **Sign up:** name, username, email, date of birth, optional gender, password. Email must be confirmed with a 6-digit code. Unconfirmed sign-ups are removed after 30 minutes.
- **Sign in:** Curie ID, username or email plus password. Sign-in from a new device needs a code emailed to the account.
- **Forgot password:** code by email, then a new password. Resetting signs out every session.
- **Account page:** edit name, username and gender; change password; see and end sessions; see and remove trusted devices.
- **Protection:** passwords hashed with PBKDF2-SHA256 (one hash runs even for unknown accounts, so response times don't reveal them); codes stored only as HMAC, with a 5-try limit and single use; sign-in is limited per identifier and IP (no account lock, so nobody can lock you out); strict security headers and a Content-Security-Policy on the pages.
- **Privacy:** date of birth, email and gender are shown only to the account owner, never on the public `/user/:id` route.

## Setup

### 1. Accounts (all free)

1. **Cloudflare:** sign up, then install the CLI: `npm install` inside `worker/`, then `npx wrangler login`.
2. **Brevo:** sign up, go to Settings → SMTP & API → create an API key. Under Senders, add and verify the email address you'll send from. Brevo won't send from an unverified address.

### 2. Create the database

```bash
cd worker
npx wrangler d1 create curie-id
```

Copy the `database_id` it prints into `wrangler.toml`, replacing `PASTE_YOUR_D1_DATABASE_ID_HERE`.

### 3. Set the settings

In `wrangler.toml`, set `MAIL_FROM_EMAIL` to your verified Brevo sender.

Set `ALLOWED_ORIGIN` to the exact origin the pages are served from, e.g. `https://id.yourdomain.com`. Leaving it as a placeholder blocks the pages.

Set the secrets (each command prompts for the value; nothing is stored in your files). Use two different random values for JWT and codes:

```bash
npx wrangler secret put JWT_SECRET        # openssl rand -hex 32
npx wrangler secret put CODE_SECRET       # a different value: openssl rand -hex 32
npx wrangler secret put BREVO_API_KEY     # from Brevo
npx wrangler secret put ADMIN_TOKEN       # optional; only needed for /admin/hash-timing
```

Rotating `JWT_SECRET` signs everyone out. Rotating `CODE_SECRET` only invalidates codes that are waiting to be entered.

### 4. Create the tables and deploy

```bash
npm run db:migrate          # creates the tables in your remote D1 database
npm run deploy              # prints your Worker URL, e.g. https://curie-id.yourname.workers.dev
```

### 5. Point the pages at the Worker

Edit `pages/config.js` and paste your Worker URL. Then host the `pages/` folder anywhere static.

The `pages/_headers` file sets the Content-Security-Policy for Cloudflare Pages. For Firebase Hosting, put the same headers in `firebase.json` under `"headers"` for your site. Check that the pages still load and sign-in works after adding them.

### 6. Measure password hashing on the free plan (do this before going live)

Workers' free plan allows **10 ms of CPU per request**. Test whether the hashing setting fits:

```bash
curl -H "X-Admin-Token: YOUR_ADMIN_TOKEN" https://curie-id.yourname.workers.dev/admin/hash-timing
```

- If it's comfortably under the limit, raise `PBKDF2_ITERATIONS` (ideally toward 600000) and redeploy.
- If sign-in fails with errors on the free plan, the hashing is over the CPU budget. Keep the lower value, or move to Workers Paid ($5/month), which raises the limit. For an identity service, paying is the better choice than a weak hash.

Each stored password records the iteration count it was made with, so raising the value later doesn't break existing logins.

## Test checklist (run before real users)

Use a test email address you can read.

1. Sign up with a valid date of birth. Confirm the code arrives and the account activates.
2. Sign up with someone under 13. It should be refused.
3. Sign up with a username or email already in use. It should be refused.
4. Sign in on a new browser (or private window). A code should arrive by email, and sign-in should complete after you enter it.
5. Enter the wrong password 5 times from one network. That identifier should be blocked from that network for 15 minutes, but signing in from another network should still work. Confirm the account is not locked for its owner.
6. Forgot password: request a code, reset, then confirm the old sessions are signed out.
7. Account page: change name and gender, change password, sign out another session, remove a device.
8. Call `GET /user/<your curie id>` without signing in. Only name and username should appear.

## Limits to watch (free plan)

- **Brevo:** 300 emails per day, shared by sign-up, sign-in-from-new-device, and reset codes.
- **D1:** 5 million rows read and 100,000 rows written per day. The daily cleanup (cron, 03:00 UTC) keeps the event and rate-limit tables small. The free plan stops answering when a daily limit is reached, until midnight UTC.
- **Workers:** 100,000 requests per day.
- **Sessions:** every signed-in request reads its session row, so a busy day uses D1 reads quickly.

These are from Cloudflare's and Brevo's published free-plan pages. Check your dashboards, since they can change.

## Known trade-offs

- **Sign-up reveals registered emails.** When someone tries to register with an email already in use, the message says so. That's a deliberate usability choice, and it means someone can check whether an email has an account.
- **Curie IDs are 12 digits plus a letter.** Chosen so collisions stay rare at large user counts. Changing the length later means updating the format check.
- **Limits can be shared by people on one network.** Sign-in limits are per IP, so a shared network (an office, a mobile carrier) can hit them.

## Not included (planned next)

- Migrating existing Firebase accounts (the lazy migration we discussed).
- Changing email or date of birth through verified flows.
- Developer app registration and "Sign in with Curie ID" for other apps (OAuth).
- An admin dashboard for accounts. The admin route here only measures hashing.
