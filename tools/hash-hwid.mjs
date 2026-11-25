import { createHash } from "node:crypto";

const hwid = process.argv[2];

if (!hwid) {
  console.error("usage: npm run hwid -- <DEVICE_ID>");
  process.exit(1);
}

const normalized = hwid.trim().toUpperCase();

if (!/^[A-Z0-9_-]{8,128}$/.test(normalized)) {
  console.error("invalid hwid format");
  process.exit(1);
}

console.log(createHash("sha256").update(normalized).digest("hex"));
