# G.AIPLAY license gate

A Cloudflare Worker that validates a purchased license key against a Roblox UserId, with optional per-license HWID binding, and only releases the protected Luau payload to licensed users. All three UIs share the same worker: each product gets its own entry in `whitelist.json` and points `loader.luau` at its own `PRODUCT` value.

## Files

| File | Purpose |
| --- | --- |
| `server.js` | Worker entry point and HTTP routes |
| `src/license.js` | Pure validation, hashing, HWID binding, and signed-token logic |
| `src/license.test.js` | Node test suite |
| `whitelist.json` | Products and licenses |
| `scripts/aiplay.luau` | Protected payload served only to licensed users |
| `loader.luau` | Executor-side loader: verify, fetch, compile, run |
| `tools/hash-key.mjs` | Converts a plain key into the hash stored in the whitelist |
| `tools/hash-hwid.mjs` | Converts a device id into the hash stored in the whitelist |
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

   To bind a license to one machine, hash the device id with `npm run hwid -- <DEVICE_ID>` and put the result in `hwidHash`:

   ```json
   {
     "keyHash": "<sha256 of the key>",
     "userId": "123456789",
     "hwidHash": "<sha256 of the device id>",
     "product": "aiplay",
     "expiresAt": null,
     "active": true
   }
   ```

   Omit `hwidHash` (or set it to `null`) to keep the key + UserId behavior. Device ids are normalized to upper case before hashing. The loader reads the id from `CONFIG.HWID` if set, otherwise from `RbxAnalyticsService:GetClientId()`, with executor-specific `HWID` or `get_hwid()` as fallbacks. Put the exact same id in `CONFIG.HWID` when you bind the license to a value that is not the Roblox client id.

4. Use the same `product` value in `loader.luau` (`aiplay`, `myui`, or `mythorith` by default). A product can be disabled globally with `enabled: false`.

5. Replace the placeholder payload in `scripts/aiplay.luau` with the real AI PLAY module. The worker bundles it at deploy time.

6. Deploy with `npm run deploy`, or run locally with `npm run dev`.

7. In `loader.luau`, set `BASE_URL`, `KEY`, and `USER_ID`, then execute it in your executor. It returns a table with `run`, `verify`, `loadSource`, and `getHwid` if you want to call it from a hub.

## Endpoints

`POST /v1/verify` (or `GET /v1/verify?product=...&key=...&userId=...&hwid=...`):

```json
{ "product": "aiplay", "key": "GAIPLAY-XXXX-XXXX-XXXX-XXXX", "userId": "123456789", "hwid": "optional-device-id", "nonce": "optional" }
```

```json
{ "ok": true, "licensed": true, "product": "aiplay", "userId": "123456789", "hwidBound": true, "token": "...", "tokenExpiresAt": 1767226200 }
```

`hwid` is optional and ignored for licenses without `hwidHash`. A bound license returns `hwid_required` when it is missing and `hwid_mismatch` when it does not match.

`GET /v1/script?token=...&product=aiplay&userId=123456789&hwid=...&name=aiplay` returns `{ "ok": true, "name": "aiplay", "source": "..." }`. It accepts `POST` with JSON or form data too. For a device-bound token the same `hwid` must be sent again.

`GET /v1/health` is an unauthenticated status endpoint. Failures return `{ "ok": false, "reason": "..." }` with an appropriate HTTP status. Invalid key, user, or product all collapse to `invalid_credentials` so the endpoint does not reveal which half of the pair was wrong.

## Verification modes

`loader.luau` supports both patterns:

- `verify()` only: check the license and leave the decision to your own hub.
- `run()`: verify, fetch the protected source, compile it, and execute it. The script is never present in the distributed loader.

## Security notes

The decision is made in the Worker, so a client cannot edit a local flag to enable the feature. The token is HMAC-SHA256 signed, bound to the product, UserId and device id, and expires after `TOKEN_TTL_SECONDS` (300 by default). The script endpoint re-checks the license on every request, so revoking an entry in `whitelist.json` and redeploying cuts off new loads even if a token is still valid. Plain keys and device ids never appear in the whitelist, and rate limiting slows credential guessing.

HWID binding stops casual key sharing between machines, but the id is supplied by the client: there is no hardware attestation here, and a determined user can spoof a known id. Treat it as a deterrent, not a cryptographic identity. Anything delivered to an executor can still be captured and replayed by a licensed user; no client-side check can prevent that. Do not put secrets that must remain private inside the protected payload. Cloudflare rate limiting rules and short token TTLs reduce the window, but the whitelist is the source of truth.

## Commands

```bash
npm test
npm run dev
npm run deploy
npm run key -- <LICENSE_KEY>
npm run hwid -- <DEVICE_ID>
```
