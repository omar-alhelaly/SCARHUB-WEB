// UNTESTED. Paymob "transaction processed" callback. The HMAC is verified before anything else; unsigned or wrong calls change nothing.
// Needs secret PAYMOB_HMAC_SECRET. Deploy with JWT verification OFF (Paymob cannot send a Supabase token): the HMAC is the authentication.
// Money is granted by paymob_confirm, which checks the stored amount and currency and ignores replays.
import { createClient } from "npm:@supabase/supabase-js@2";

const KEYS = ["amount_cents", "created_at", "currency", "error_occured", "has_parent_transaction", "id", "integration_id", "is_3d_secure", "is_auth", "is_capture",
  "is_refunded", "is_standalone_payment", "is_voided", "order.id", "owner", "pending", "source_data.pan", "source_data.sub_type", "source_data.type", "success"];
// deno-lint-ignore no-explicit-any
const get = (o: any, p: string) => p.split(".").reduce((a, k) => (a == null ? undefined : a[k]), o);
const ok = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "Content-Type": "application/json" } });

async function hmacHex(secret: string, msg: string) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg)));
  return [...sig].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function same(a: string, b: string) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }

Deno.serve(async (req) => {
  if (req.method !== "POST") return ok({ error: "method" }, 405);
  const secret = Deno.env.get("PAYMOB_HMAC_SECRET");
  if (!secret) return ok({ error: "not configured" }, 503);
  const got = new URL(req.url).searchParams.get("hmac") ?? "";
  const body = await req.json().catch(() => null);
  const obj = body?.obj;
  if (!obj || body.type !== "TRANSACTION") return ok({ error: "bad" }, 400);
  const msg = KEYS.map((k) => String(get(obj, k) ?? "")).join("");
  if (!same(await hmacHex(secret, msg), got.toLowerCase())) return ok({ error: "signature" }, 401);   // unsigned / tampered / replay with edits
  const rid = obj.order?.merchant_order_id;
  if (typeof rid !== "string" || !/^[0-9a-f-]{36}$/.test(rid)) return ok({ error: "ref" }, 400);
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const ignore = obj.is_refunded === true || obj.is_voided === true || obj.pending === true;
  if (ignore) return ok({ result: "ignored" });
  const { data, error } = await admin.rpc("paymob_confirm", {
    p_request: rid, p_order: String(obj.order.id), p_amount: Number(obj.amount_cents), p_currency: String(obj.currency), p_success: obj.success === true && obj.error_occured !== true,
  });
  if (error) return ok({ error: "retry" }, 500);   // 5xx so Paymob retries; paymob_confirm is replay-safe
  return ok({ result: data });
});
