import test from "node:test";
import assert from "node:assert/strict";
import {
  checkLicense,
  findLicenseByKeyId,
  hwidIdFor,
  isProductActive,
  issueToken,
  licenseUsable,
  normalizeHwid,
  normalizeKey,
  normalizeUserId,
  safeEqual,
  sha256Hex,
  tokenHwidMatches,
  verifyToken,
} from "./license.js";

const SECRET = "test-signing-secret";
const NOW = Math.floor(Date.UTC(2026, 0, 1) / 1000);
const KEY = "GAIPLAY-TEST-0001";
const OTHER_KEY = "GAIPLAY-TEST-0002";
const DEVICE = "ABC-123-DEVICE-01";
const OTHER_DEVICE = "OTHER-DEVICE-0002";

const whitelist = {
  products: {
    aiplay: { label: "G.AIPLAY", enabled: true, expiresAt: null },
    mythorith: { label: "Mythorith Hub", enabled: true, expiresAt: null },
    myui: { label: "My UI", enabled: false, expiresAt: null },
  },
  licenses: [],
};

whitelist.licenses.push({
  keyHash: await sha256Hex(KEY),
  userId: "123456789",
  product: "aiplay",
  expiresAt: null,
  active: true,
});
whitelist.licenses.push({
  keyHash: await sha256Hex(OTHER_KEY),
  userId: "987654321",
  product: "aiplay",
  expiresAt: new Date((NOW - 10) * 1000).toISOString(),
  active: true,
});
whitelist.licenses.push({
  keyHash: await sha256Hex("GAIPLAY-TEST-0003"),
  userId: "555555555",
  product: "mythorith",
  expiresAt: null,
  active: false,
});
whitelist.licenses.push({
  keyHash: await sha256Hex("GAIPLAY-TEST-0004"),
  userId: "222222222",
  hwidHash: await sha256Hex(DEVICE),
  product: "aiplay",
  expiresAt: null,
  active: true,
});

test("normalizeKey uppercases and rejects malformed keys", () => {
  assert.equal(normalizeKey(" gaiplay-test-0001 "), KEY);
  assert.equal(normalizeKey("short"), null);
  assert.equal(normalizeKey(null), null);
});

test("normalizeUserId accepts numeric and string ids", () => {
  assert.equal(normalizeUserId(123456789), "123456789");
  assert.equal(normalizeUserId(" 00042 "), "00042");
  assert.equal(normalizeUserId("abc"), null);
  assert.equal(normalizeUserId(-1), null);
});

test("safeEqual compares without early exit", () => {
  assert.equal(safeEqual("abcdef", "abcdef"), true);
  assert.equal(safeEqual("abcdef", "abcdeg"), false);
  assert.equal(safeEqual("abc", "abcdef"), false);
});

test("checkLicense accepts a matching key and user", async () => {
  const result = await checkLicense({
    whitelist,
    product: "aiplay",
    key: KEY.toLowerCase(),
    userId: 123456789,
    now: NOW,
  });
  assert.equal(result.ok, true);
  assert.equal(result.userId, "123456789");
  assert.equal(result.keyId.length, 12);
});

test("checkLicense rejects wrong user, wrong product and wrong key", async () => {
  const base = { whitelist, product: "aiplay", key: KEY, now: NOW };
  assert.equal((await checkLicense({ ...base, userId: "999" })).reason, "invalid_credentials");
  assert.equal((await checkLicense({ ...base, userId: "123456789", product: "mythorith" })).reason, "invalid_credentials");
  assert.equal((await checkLicense({ ...base, userId: "123456789", key: "GAIPLAY-WRONG-99" })).reason, "invalid_credentials");
});

test("checkLicense rejects expired, inactive and disabled products", async () => {
  assert.equal((await checkLicense({ whitelist, product: "aiplay", key: OTHER_KEY, userId: "987654321", now: NOW })).reason, "license_expired");
  assert.equal((await checkLicense({ whitelist, product: "mythorith", key: "GAIPLAY-TEST-0003", userId: "555555555", now: NOW })).reason, "license_inactive");
  assert.equal((await checkLicense({ whitelist, product: "myui", key: KEY, userId: "123456789", now: NOW })).reason, "product_unavailable");
  assert.equal(isProductActive(whitelist, "myui", NOW), false);
});

test("issued token verifies and binds user and product", async () => {
  const issued = await issueToken({
    secret: SECRET,
    product: "aiplay",
    userId: "123456789",
    keyId: (await sha256Hex(KEY)).slice(0, 12),
    ttlSeconds: 300,
    now: NOW,
  });
  const verified = await verifyToken({ token: issued.token, secret: SECRET, now: NOW + 60 });
  assert.equal(verified.ok, true);
  assert.equal(verified.payload.u, "123456789");
  assert.equal(verified.payload.p, "aiplay");
  assert.equal(verified.payload.exp, NOW + 300);
});

test("token rejects tampering, wrong secret and expiry", async () => {
  const issued = await issueToken({
    secret: SECRET,
    product: "aiplay",
    userId: "123456789",
    keyId: (await sha256Hex(KEY)).slice(0, 12),
    ttlSeconds: 60,
    now: NOW,
  });
  const tampered = issued.token.slice(0, -2) + "xx";
  assert.equal((await verifyToken({ token: tampered, secret: SECRET, now: NOW })).reason, "invalid_token");
  assert.equal((await verifyToken({ token: issued.token, secret: "other", now: NOW })).reason, "invalid_token");
  assert.equal((await verifyToken({ token: issued.token, secret: SECRET, now: NOW + 61 })).reason, "token_expired");
  assert.equal((await verifyToken({ token: "nope", secret: SECRET, now: NOW })).reason, "invalid_token");
});

test("revocation is enforced through the token key id", async () => {
  const keyId = (await sha256Hex(KEY)).slice(0, 12);
  const license = findLicenseByKeyId(whitelist, keyId, "123456789", "aiplay");
  assert.equal(licenseUsable(license, NOW), true);
  assert.equal(findLicenseByKeyId(whitelist, "ffffffffffff", "123456789", "aiplay"), null);
  assert.equal(licenseUsable({ ...license, active: false }, NOW), false);
});

test("normalizeHwid uppercases and rejects malformed ids", () => {
  assert.equal(normalizeHwid(" abc-123-device-01 "), DEVICE);
  assert.equal(normalizeHwid("short"), null);
  assert.equal(normalizeHwid(12345), null);
});

test("device-bound license requires a matching hwid", async () => {
  const base = { whitelist, product: "aiplay", key: "GAIPLAY-TEST-0004", userId: "222222222", now: NOW };
  const result = await checkLicense({ ...base, hwid: DEVICE.toLowerCase() });
  assert.equal(result.ok, true);
  assert.equal(result.hwidId, (await sha256Hex(DEVICE)).slice(0, 12));
  assert.equal((await checkLicense({ ...base, hwid: null })).reason, "hwid_required");
  assert.equal((await checkLicense({ ...base, hwid: OTHER_DEVICE })).reason, "hwid_mismatch");
});

test("hwid is ignored for licenses that are not device-bound", async () => {
  const result = await checkLicense({
    whitelist,
    product: "aiplay",
    key: KEY,
    userId: "123456789",
    hwid: OTHER_DEVICE,
    now: NOW,
  });
  assert.equal(result.ok, true);
  assert.equal(result.hwidId, null);
});

test("token binds the hwid id and rejects a different device", async () => {
  const keyId = (await sha256Hex(KEY)).slice(0, 12);
  const hwidId = await hwidIdFor(DEVICE);
  const issued = await issueToken({
    secret: SECRET,
    product: "aiplay",
    userId: "123456789",
    keyId,
    hwidId,
    ttlSeconds: 300,
    now: NOW,
  });
  const verified = await verifyToken({ token: issued.token, secret: SECRET, now: NOW });
  assert.equal(verified.payload.h, hwidId);
  assert.equal((await hwidIdFor(OTHER_DEVICE)) === verified.payload.h, false);
  assert.equal(tokenHwidMatches(hwidId, { hwidHash: await sha256Hex(DEVICE) }), true);
  assert.equal(tokenHwidMatches(hwidId, { hwidHash: await sha256Hex(OTHER_DEVICE) }), false);
  assert.equal(tokenHwidMatches(null, { hwidHash: await sha256Hex(DEVICE) }), false);
});
