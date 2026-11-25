import { createHash } from "node:crypto";

const key = process.argv[2];

if (!key) {
  console.error("usage: npm run key -- <LICENSE_KEY>");
  process.exit(1);
}

const normalized = key.trim().toUpperCase();

if (!/^[A-Z0-9-]{8,96}$/.test(normalized)) {
  console.error("invalid key format");
  process.exit(1);
}

console.log(createHash("sha256").update(normalized).digest("hex"));
