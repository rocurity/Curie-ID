# Sign in with Curie ID: developer guide

Curie ID lets people use one account across your app. Your app never sees the person's password. It uses the standard OAuth 2.0 authorization code flow with PKCE, so any OAuth library works.

## 1. Register your app

Ask the Curie ID owner to add your app to the `APPS_JSON` setting. You provide:

- **clientId**: a short unique name, for example `insaka-web`
- **name**: what users see on the consent screen
- **redirectUris**: the exact addresses Curie ID may send users back to. Use `https://` for live sites, and `http://localhost` only while testing.

## 2. Send the user to Curie ID

Create a random `code_verifier` (43 to 128 characters) and keep it. Its SHA-256 hash, encoded as base64url, is the `code_challenge`. Also create a random `state`. Then send the user to:

```
https://curie-id.pages.dev/authorize.html?client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT&code_challenge=CHALLENGE&code_challenge_method=S256&state=STATE
```

Curie ID shows the sign-in and consent screens. Users can cancel.

## 3. Exchange the code for a token

When the user approves, Curie ID sends them to your redirect address with `?code=...&state=...`. Check that `state` matches the one you sent. Then:

```
POST https://curie-id.rocurity.workers.dev/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=CODE&redirect_uri=YOUR_REDIRECT&client_id=YOUR_CLIENT_ID&code_verifier=VERIFIER
```

The response contains `access_token`, valid for one hour. Each code works once and expires after one minute.

## 4. Read the user

```
GET https://curie-id.rocurity.workers.dev/oauth/userinfo
Authorization: Bearer ACCESS_TOKEN
```

You get back:

```json
{ "sub": "123456789012c", "name": "Peter Cherub", "preferred_username": "peter" }
```

`sub` is the user's Curie ID. Use it as the unique key for the user in your app. Curie ID never shares email, date of birth or gender with apps.

## Keeping the user signed in

Call `POST https://curie-id.rocurity.workers.dev/auth/refresh` with the current access token before it expires. You get a new token. If the user signs out everywhere, disconnects your app, or the session ends after 30 days, the refresh fails. Send the user through sign-in again.

## Rules

- Always use PKCE. Curie ID refuses requests without it.
- Use the redirect address exactly as registered. Any difference is refused.
- Don't put the access token in a URL. Keep it in memory or session storage.
- Don't store passwords. Your app never needs them.

## Try it

The example app in `pages/example/` runs the whole flow. Open it on the pages site and press "Sign in with Curie ID".
