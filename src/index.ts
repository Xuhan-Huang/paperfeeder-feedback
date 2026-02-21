// Minimal Cloudflare Worker endpoint for one-click feedback capture.
// Route: GET /feedback?t=<signed_token>
// Env bindings:
// - DB (D1 database)
// - FEEDBACK_LINK_SIGNING_SECRET (secret text)

function b64urlToBytes(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const base64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyToken(token, secret) {
  if (!token || !token.includes(".")) throw new Error("invalid token format");
  const [payloadB64, sigB64] = token.split(".", 2);
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(payloadB64)));
  const got = b64urlToBytes(sigB64);
  if (bytesToHex(expected) !== bytesToHex(got)) throw new Error("invalid signature");

  const payloadJson = new TextDecoder().decode(b64urlToBytes(payloadB64));
  const claims = JSON.parse(payloadJson);
  if (!claims || !claims.exp) throw new Error("invalid claims");
  if (new Date(claims.exp).getTime() < Date.now()) throw new Error("token expired");
  if (!["positive", "negative", "undecided"].includes(String(claims.label || "").toLowerCase())) {
    throw new Error("invalid label");
  }
  return claims;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/feedback") return new Response("Not Found", { status: 404 });
    const token = url.searchParams.get("t") || "";
    try {
      const claims = await verifyToken(token, env.FEEDBACK_LINK_SIGNING_SECRET);
      const eventId = `evt_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
      const createdAt = new Date().toISOString();
      await env.DB
        .prepare(
          `INSERT INTO feedback_events
           (event_id, run_id, item_id, label, reviewer, created_at, source, status, resolved_semantic_paper_id, applied_at, error)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, NULL)`
        )
        .bind(
          eventId,
          String(claims.run_id || ""),
          String(claims.item_id || ""),
          String(claims.label || "").toLowerCase(),
          String(claims.reviewer || ""),
          createdAt,
          "email_link"
        )
        .run();
      return new Response(
        `Feedback recorded: run=${claims.run_id}, item=${claims.item_id}, label=${claims.label}`,
        { status: 200 }
      );
    } catch (err) {
      return new Response(`Feedback rejected: ${err.message}`, { status: 400 });
    }
  },
};
