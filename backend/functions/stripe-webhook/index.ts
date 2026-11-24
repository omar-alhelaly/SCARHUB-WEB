// Stripe -> subscriptions table. Signature is verified. Any failure returns 5xx so Stripe retries.
// Retry-safe: every handler re-fetches the subscription from Stripe and upserts by user_id, so replays and out-of-order events converge on the latest state.
import { createClient } from "npm:@supabase/supabase-js@2";
import Stripe from "npm:stripe@16";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const fail = (msg: string, status = 500) => { console.error("stripe-webhook:", msg); return new Response(msg, { status }); };

async function sync(subId: string, userIdHint?: string | null): Promise<string | null> {
  const sub = await stripe.subscriptions.retrieve(subId);               // fresh state, not the possibly stale event payload
  const uid = userIdHint || sub.metadata?.user_id;
  if (!uid) return "no user id for subscription " + subId;
  const end = sub.current_period_end ?? (sub as any).items?.data?.[0]?.current_period_end;
  if (!end) return "no period end for " + subId;
  const { error } = await admin.from("subscriptions").upsert({
    user_id: uid, status: sub.status, provider: "stripe", provider_customer_id: String(sub.customer),
    provider_sub_id: sub.id, current_period_end: new Date(end * 1000).toISOString(), updated_at: new Date().toISOString(),
  }, { onConflict: "user_id" });
  return error ? "db write failed: " + error.message : null;
}

Deno.serve(async (req) => {
  const sig = req.headers.get("stripe-signature");
  if (!sig) return fail("missing signature", 400);
  let ev: Stripe.Event;
  try {
    ev = await stripe.webhooks.constructEventAsync(await req.text(), sig, Deno.env.get("STRIPE_WEBHOOK_SECRET")!);
  } catch { return fail("bad signature", 400); }
  try {
    let err: string | null = null;
    if (ev.type === "checkout.session.completed") {
      const s = ev.data.object as Stripe.Checkout.Session;
      if (s.mode === "subscription" && s.subscription) err = await sync(String(s.subscription), s.client_reference_id);
    } else if (ev.type === "customer.subscription.created" || ev.type === "customer.subscription.updated" || ev.type === "customer.subscription.deleted") {
      err = await sync((ev.data.object as Stripe.Subscription).id);
    }
    if (err) return fail(err);                                           // 500 -> Stripe retries with backoff
  } catch (e) { return fail("handler error: " + (e as Error).message); }
  return new Response("ok");
});
