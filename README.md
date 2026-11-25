# G.AIPLAY license gate

A Cloudflare Worker that validates a purchased license key against a Roblox UserId and only releases the protected Luau payload to licensed users. All three UIs share the same worker: each product gets its own entry in `whitelist.json` and points `loader.luau` at its own `PRODUCT` value.

## Files

| File | Purpose |
| --- | --- |
| `server.js` | Worker entry point and HTTP routes |
| `src/license.js` | Pure validation, hashing, and signed-token logic |
| `src/license.test.js` | Node test suite |
| `whitelist.json` | Products and licenses |
| `scripts/aiplay.luau` | Protected payload served only to licensed users |
| `loader.luau` | Executor-side loader: verify, fetch, compile, run |
| `tools/hash-key.mjs` | Converts a plain key into the hash stored in the whitelist |
| `wrangler.jsonc` | Wrangler config, including the `.luau` text module rule |

## Setup

1. `npm install`
2. Generate a signing secret and store it in the Worker:

   ```bash
   npx wrangler secret put TOKEN_SECRET
   ```

   For local development put the same value in `.dev.vars` as `TOKEN_SECRET=...`.

3. Hash each license key with `npm run key -- GAIPLAY-XXXX-XXXX-XXXX-XXXX` and add the result to `whitelist.json`:

   ```json
   {
     "keyHash": "<sha256 hex from the command above>",
     "userId": "123456789",
     "product": "aiplay",
     "expiresAt": null,
     "active": true,
     "note": "optional label"
   }
   ```

   Keys are normalized to upper case before hashing. `expiresAt` accepts an ISO date string or a Unix timestamp; `null` means no expiry. Setting `active` to `false` revokes the license immediately.

4. Use the same `product` value in `loader.luau` (`aiplay`, `myui`, or `mythorith` by default). A product can be disabled globally with `enabled: false`.

5. Replace the placeholder payload in `scripts/aiplay.luau` with the real AI PLAY module. The worker bundles it at deploy time.

6. Deploy with `npm run deploy`, or run locally with `npm run dev`.

7. In `loader.luau`, set `BASE_URL`, `KEY`, and `USER_ID`, then execute it in your executor. It returns a table with `run`, `verify`, and `loadSource` if you want to call it from a hub.

## Endpoints

`POST /v1/verify` (or `GET /v1/verify?product=...&key=...&userId=...`):

```json
{ "product": "aiplay", "key": "GAIPLAY-XXXX-XXXX-XXXX-XXXX", "userId": "123456789", "nonce": "optional" }
```

```json
{ "ok": true, "licensed": true, "product": "aiplay", "userId": "123456789", "token": "...", "tokenExpiresAt": 1767226200 }
```

`GET /v1/script?token=...&product=aiplay&userId=123456789&name=aiplay` returns `{ "ok": true, "name": "aiplay", "source": "..." }`. It accepts `POST` with JSON or form data too.

`GET /v1/health` is an unauthenticated status endpoint. Failures return `{ "ok": false, "reason": "..." }` with an appropriate HTTP status. Invalid key, user, or product all collapse to `invalid_credentials` so the endpoint does not reveal which half of the pair was wrong.

## Verification modes

`loader.luau` supports both patterns:

- `verify()` only: check the license and leave the decision to your own hub.
- `run()`: verify, fetch the protected source, compile it, and execute it. The script is never present in the distributed loader.

## Security notes

The decision is made in the Worker, so a client cannot edit a local flag to enable the feature. The token is HMAC-SHA256 signed, bound to the product and UserId, and expires after `TOKEN_TTL_SECONDS` (300 by default). The script endpoint re-checks the license on every request, so revoking an entry in `whitelist.json` and redeploying cuts off new loads even if a token is still valid. Plain keys never appear in the whitelist, and rate limiting slows credential guessing.

Anything delivered to an executor can still be captured and replayed by a licensed user; no client-side check can prevent that. Do not put secrets that must remain private inside the protected payload. Cloudflare rate limiting rules and short token TTLs reduce the window, but the whitelist is the source of truth.

## Commands

```bash
npm test
npm run dev
npm run deploy
npm run key -- <LICENSE_KEY>
```
