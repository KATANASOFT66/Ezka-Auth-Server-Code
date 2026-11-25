const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KEY_PATTERN = /^[A-Z0-9-]{8,96}$/;
const HWID_PATTERN = /^[A-Z0-9_-]{8,128}$/;
const HWID_ID_PATTERN = /^[0-9a-f]{12}$/;

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(text) {
  const normalized = String(text).replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function expires(expiresAt, now) {
  if (expiresAt === null || expiresAt === undefined || expiresAt === "") return false;
  let timestamp;
  if (typeof expiresAt === "number") {
    timestamp = expiresAt < 1e12 ? expiresAt * 1000 : expiresAt;
  } else {
    timestamp = Date.parse(expiresAt);
  }
  return !Number.isFinite(timestamp) || timestamp <= now * 1000;
}

export function normalizeUserId(value) {
  let text = value;
  if (typeof text === "number") {
    if (!Number.isSafeInteger(text) || text <= 0) return null;
    text = String(text);
  }
  if (typeof text !== "string") return null;
  const trimmed = text.trim();
  return /^\d{1,20}$/.test(trimmed) ? trimmed : null;
}

export function normalizeKey(value) {
  if (typeof value !== "string") return null;
  const key = value.trim().toUpperCase();
  return KEY_PATTERN.test(key) ? key : null;
}

export function normalizeHwid(value) {
  if (typeof value !== "string") return null;
  const hwid = value.trim().toUpperCase();
  return HWID_PATTERN.test(hwid) ? hwid : null;
}

export async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

export function isProductActive(whitelist, product, now = nowSeconds()) {
  const entry = whitelist && whitelist.products ? whitelist.products[product] : null;
  if (!entry || entry.enabled === false) return false;
  return !expires(entry.expiresAt, now);
}

export async function checkLicense({ whitelist, product, key, userId, hwid, now = nowSeconds() }) {
  if (typeof product !== "string" || !isProductActive(whitelist, product, now)) {
    return { ok: false, reason: "product_unavailable" };
  }

  const normalizedKey = normalizeKey(key);
  const normalizedUserId = normalizeUserId(userId);
  if (!normalizedKey || !normalizedUserId) return { ok: false, reason: "invalid_credentials" };

  const normalizedHwid = normalizeHwid(hwid);
  const keyHash = await sha256Hex(normalizedKey);
  const licenses = whitelist && Array.isArray(whitelist.licenses) ? whitelist.licenses : [];

  for (const entry of licenses) {
    if (!safeEqual(entry.keyHash, keyHash)) continue;
    if (entry.userId !== normalizedUserId || entry.product !== product) continue;

    const storedHwidHash = typeof entry.hwidHash === "string" && entry.hwidHash.length > 0
      ? entry.hwidHash.toLowerCase()
      : null;

    if (storedHwidHash) {
      if (!normalizedHwid) return { ok: false, reason: "hwid_required" };
      const submittedHwidHash = await sha256Hex(normalizedHwid);
      if (!safeEqual(storedHwidHash, submittedHwidHash)) return { ok: false, reason: "hwid_mismatch" };
    }

    if (entry.active === false) return { ok: false, reason: "license_inactive" };
    if (expires(entry.expiresAt, now)) return { ok: false, reason: "license_expired" };

    return {
      ok: true,
      userId: normalizedUserId,
      keyId: keyHash.slice(0, 12),
      keyHash,
      hwidId: storedHwidHash ? storedHwidHash.slice(0, 12) : null,
    };
  }

  return { ok: false, reason: "invalid_credentials" };
}

export function findLicenseByKeyId(whitelist, keyId, userId, product) {
  if (typeof keyId !== "string" || !/^[0-9a-f]{12}$/.test(keyId)) return null;
  const licenses = whitelist && Array.isArray(whitelist.licenses) ? whitelist.licenses : [];
  return licenses.find((entry) =>
    typeof entry.keyHash === "string" &&
    entry.keyHash.startsWith(keyId) &&
    entry.userId === userId &&
    entry.product === product
  ) || null;
}

export function licenseUsable(license, now = nowSeconds()) {
  return Boolean(license) && license.active !== false && !expires(license.expiresAt, now);
}

export async function hwidIdFor(value) {
  const normalized = normalizeHwid(value);
  return normalized ? (await sha256Hex(normalized)).slice(0, 12) : null;
}

export function tokenHwidMatches(hwidId, license) {
  if (!HWID_ID_PATTERN.test(hwidId) || !license || typeof license.hwidHash !== "string") return false;
  return license.hwidHash.toLowerCase().startsWith(hwidId);
}

async function signHmac(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return base64UrlEncode(new Uint8Array(signature));
}

function randomId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function issueToken({
  secret,
  product,
  userId,
  keyId,
  hwidId = null,
  nonce,
  ttlSeconds = 300,
  now = nowSeconds(),
}) {
  const payload = {
    v: 1,
    p: product,
    u: userId,
    k: keyId,
    h: hwidId && HWID_ID_PATTERN.test(hwidId) ? hwidId : null,
    iat: now,
    exp: now + ttlSeconds,
    jti: typeof nonce === "string" && nonce.length > 0 ? nonce.slice(0, 128) : randomId(),
  };
  const encoded = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const signature = await signHmac(encoded, secret);
  return { token: `${encoded}.${signature}`, payload };
}

export async function verifyToken({ token, secret, now = nowSeconds() }) {
  if (typeof token !== "string") return { ok: false, reason: "invalid_token" };
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return { ok: false, reason: "invalid_token" };

  const [encoded, signature] = parts;
  const expected = await signHmac(encoded, secret);
  if (!safeEqual(signature, expected)) return { ok: false, reason: "invalid_token" };

  let payload;
  try {
    payload = JSON.parse(decoder.decode(base64UrlDecode(encoded)));
  } catch {
    return { ok: false, reason: "invalid_token" };
  }

  if (!payload || typeof payload !== "object") return { ok: false, reason: "invalid_token" };
  if (payload.v !== 1 || typeof payload.p !== "string" || typeof payload.u !== "string") {
    return { ok: false, reason: "invalid_token" };
  }
  if (payload.h !== null && payload.h !== undefined && !HWID_ID_PATTERN.test(payload.h)) {
    return { ok: false, reason: "invalid_token" };
  }
  if (typeof payload.iat !== "number" || payload.iat > now + 30) return { ok: false, reason: "invalid_token" };
  if (typeof payload.exp !== "number" || payload.exp <= now) return { ok: false, reason: "token_expired" };

  return { ok: true, payload };
}
