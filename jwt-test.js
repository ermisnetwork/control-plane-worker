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
  const secret = process.env.JWT_SECRET || "dev-test-secret";
  const workerUrl = process.env.WORKER_URL || "https://test-control-plane-worker.ermis-network.workers.dev";
  const streamId = process.env.STREAM_ID || "019e4f4a-6f6a-7270-a7c4-6cc8507150e5";
  const streamSessionId = process.env.STREAM_SESSION_ID || "session";
  const nodeId = process.env.NODE_ID || "node-obs-test-vaapi-9998";
  const originBaseUrl = process.env.ORIGIN_BASE_URL || "http://localhost:9990";
  const routeVersion = Number(process.env.ROUTE_VERSION || "1");
  const playlist = process.env.PLAYLIST || "master";
  const scope = (process.env.SCOPE || "hls:master,hls:playlist")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  const token = await generateToken(secret, {
    stream_id: streamId,
    stream_session_id: streamSessionId,
    node_id: nodeId,
    origin_base_url: originBaseUrl,
    route_version: routeVersion,
    scope,
  });

  let playlistPath;
  if (playlist === "master") {
    playlistPath = `/hls/t/${token}/live/${encodeURIComponent(streamId)}/master.m3u8`;
  } else if (playlist === "source") {
    playlistPath = `/hls/t/${token}/live/${encodeURIComponent(streamId)}/playlist.m3u8`;
  } else {
    playlistPath = `/hls/t/${token}/live/${encodeURIComponent(streamId)}/${encodeURIComponent(playlist)}/playlist.m3u8`;
  }

  console.log("JWT:", token);
  console.log("URL:", `${workerUrl}${playlistPath}`);

  const res = await fetch(`${workerUrl}${playlistPath}`);

  console.log("Status:", res.status, res.statusText);
  console.log("Body:");
  console.log(await res.text());
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
