import test from "node:test";
import assert from "node:assert/strict";
import {
  checkLicense,
  findLicenseByKeyId,
  isProductActive,
  issueToken,
  licenseUsable,
  normalizeKey,
  normalizeUserId,
  safeEqual,
  sha256Hex,
  verifyToken,
} from "./license.js";

const SECRET = "test-signing-secret";
const NOW = Math.floor(Date.UTC(2026, 0, 1) / 1000);
const KEY = "GAIPLAY-TEST-0001";
const OTHER_KEY = "GAIPLAY-TEST-0002";

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
