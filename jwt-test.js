const { webcrypto } = require("node:crypto");

const cryptoApi = globalThis.crypto || webcrypto;
const textEncoder = new TextEncoder();

function base64url(input) {
  const bytes = input instanceof Uint8Array ? input : textEncoder.encode(input);
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function generateToken(secret, claims = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "HS256",
    typ: "JWT",
  };
  const payload = {
    sub: "local-test",
    iat: now,
    exp: now + 10 * 60,
    ...claims,
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await cryptoApi.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await cryptoApi.subtle.sign(
    "HMAC",
    key,
    textEncoder.encode(signingInput),
  );

  return `${signingInput}.${base64url(new Uint8Array(signature))}`;
}

async function main() {
  const secret = process.env.JWT_SECRET || "dev-test-secret-wrong";
  const workerUrl = process.env.WORKER_URL || "https://control-plane-worker.ermis-network.workers.dev";
  const streamPath = process.env.STREAM_PATH || "/hls/app/stream/master.m3u8";
  const token = await generateToken(secret);

  console.log("JWT:", token);

  const res = await fetch(`${workerUrl}${streamPath}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  console.log("Status:", res.status, res.statusText);
  console.log("Body:");
  console.log(await res.text());
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
