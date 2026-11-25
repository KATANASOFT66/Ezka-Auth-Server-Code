import whitelist from "./whitelist.json";
import aiplaySource from "./scripts/aiplay.luau";
import {
  checkLicense,
  findLicenseByKeyId,
  hwidIdFor,
  isProductActive,
  issueToken,
  licenseUsable,
  normalizeUserId,
  tokenHwidMatches,
  verifyToken,
} from "./src/license.js";

const SOURCES = Object.freeze({ aiplay: aiplaySource });
const RATE_WINDOW_MS = 60000;
const RATE_LIMIT = 45;
const MAX_BODY_LENGTH = 8192;
const attempts = new Map();

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function headers(extra = {}) {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Content-Type, Accept",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-type": "application/json; charset=utf-8",
    ...extra,
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: headers() });
}

function preflight() {
  return new Response(null, { status: 204, headers: headers() });
}

function rateLimited(request) {
  const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("x-forwarded-for") || "unknown";
  const timestamp = Date.now();
  const record = attempts.get(ip);

  if (attempts.size > 5000) attempts.clear();

  if (!record || timestamp - record.start > RATE_WINDOW_MS) {
    attempts.set(ip, { start: timestamp, count: 1 });
    return false;
  }

  record.count += 1;
  return record.count > RATE_LIMIT;
}

async function readParams(request, url) {
  const params = new Map();
  for (const [key, value] of url.searchParams) params.set(key.toLowerCase(), value);

  if (request.method === "POST") {
    const raw = await request.text();
    if (raw.length > MAX_BODY_LENGTH) return null;

    const contentType = request.headers.get("content-type") || "";
    let entries = [];

    if (contentType.toLowerCase().includes("json")) {
      try {
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
        entries = Object.entries(parsed);
      } catch {
        return null;
      }
    } else {
      entries = Array.from(new URLSearchParams(raw).entries());
    }

    for (const [key, value] of entries) {
      if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        params.set(key.toLowerCase(), String(value));
      }
    }
  }

  return params;
}

function getParam(params, ...names) {
  for (const name of names) {
    const value = params.get(name.toLowerCase());
    if (typeof value === "string" && value.length > 0) return value;
  }
  return null;
}

async function handleVerify(request, url, env) {
  if (rateLimited(request)) {
    return json({ ok: false, licensed: false, reason: "rate_limited" }, 429);
  }

  const params = await readParams(request, url);
  if (!params) return json({ ok: false, licensed: false, reason: "invalid_request" }, 400);

  const product = getParam(params, "product") || "aiplay";
  const key = getParam(params, "key", "license", "licensekey");
  const userId = getParam(params, "userid", "user", "user_id");
  const hwid = getParam(params, "hwid", "hardwareid", "machineid", "clientid");
  const nonce = getParam(params, "nonce");

  const result = await checkLicense({ whitelist, product, key, userId, hwid });
  if (!result.ok) {
    return json({ ok: false, licensed: false, reason: result.reason, serverTime: nowSeconds() }, 401);
  }

  const secret = env && env.TOKEN_SECRET;
  if (!secret) return json({ ok: false, licensed: false, reason: "server_misconfigured" }, 500);

  const ttl = Number(env.TOKEN_TTL_SECONDS) || 300;
  const issued = await issueToken({
    secret,
    product,
    userId: result.userId,
    keyId: result.keyId,
    hwidId: result.hwidId,
    nonce,
    ttlSeconds: ttl,
    now: nowSeconds(),
  });

  return json({
    ok: true,
    licensed: true,
    product,
    userId: result.userId,
    hwidBound: Boolean(result.hwidId),
    token: issued.token,
    tokenExpiresAt: issued.payload.exp,
    serverTime: nowSeconds(),
  });
}

async function handleScript(request, url, env) {
  if (rateLimited(request)) return json({ ok: false, reason: "rate_limited" }, 429);

  const params = await readParams(request, url);
  if (!params) return json({ ok: false, reason: "invalid_request" }, 400);

  const token = getParam(params, "token");
  const product = getParam(params, "product") || "aiplay";
  const userId = normalizeUserId(getParam(params, "userid"));
  const name = getParam(params, "name", "script") || "aiplay";
  const hwid = getParam(params, "hwid", "hardwareid", "machineid", "clientid");
  const secret = env && env.TOKEN_SECRET;

  if (!secret) return json({ ok: false, reason: "server_misconfigured" }, 500);

  const verified = await verifyToken({ token, secret, now: nowSeconds() });
  if (!verified.ok) return json({ ok: false, reason: verified.reason }, 401);

  const payload = verified.payload;
  if (payload.p !== product || payload.u !== userId) {
    return json({ ok: false, reason: "invalid_token" }, 401);
  }

  if (!isProductActive(whitelist, product, nowSeconds())) {
    return json({ ok: false, reason: "product_unavailable" }, 403);
  }

  const license = findLicenseByKeyId(whitelist, payload.k, payload.u, payload.p);
  if (!licenseUsable(license, nowSeconds())) {
    return json({ ok: false, reason: "license_revoked" }, 403);
  }

  const tokenHwid = payload.h || null;
  if (tokenHwid) {
    if (!tokenHwidMatches(tokenHwid, license)) {
      return json({ ok: false, reason: "license_revoked" }, 403);
    }
    if ((await hwidIdFor(hwid)) !== tokenHwid) {
      return json({ ok: false, reason: "hwid_mismatch" }, 401);
    }
  }

  if (!Object.prototype.hasOwnProperty.call(SOURCES, name)) {
    return json({ ok: false, reason: "unknown_script" }, 404);
  }

  return json({ ok: true, name, source: SOURCES[name], tokenExpiresAt: payload.exp });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, "") || "/";

      if (request.method === "OPTIONS") return preflight();

      if (path === "/" || path === "/health" || path === "/v1/health") {
        return json({ ok: true, service: "G.AIPLAY", version: 1, time: nowSeconds() });
      }

      if (path === "/v1/verify") {
        if (request.method !== "GET" && request.method !== "POST") {
          return json({ ok: false, reason: "method_not_allowed" }, 405);
        }
        return handleVerify(request, url, env);
      }

      if (path === "/v1/script") {
        if (request.method !== "GET" && request.method !== "POST") {
          return json({ ok: false, reason: "method_not_allowed" }, 405);
        }
        return handleScript(request, url, env);
      }

      return json({ ok: false, reason: "not_found" }, 404);
    } catch {
      return json({ ok: false, reason: "internal_error" }, 500);
    }
  },
};
