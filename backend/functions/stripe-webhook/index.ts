// Stripe -> subscriptions table. Signature is verified; nothing else can write subscriptions.
import { createClient } from "npm:@supabase/supabase-js@2";
import Stripe from "npm:stripe@16";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
Deno.serve(async (req) => {
  const sig = req.headers.get("stripe-signature");
  if (!sig) return new Response("no", { status: 400 });
  let ev: Stripe.Event;
  try {
    ev = await stripe.webhooks.constructEventAsync(await req.text(), sig, Deno.env.get("STRIPE_WEBHOOK_SECRET")!);
  } catch { return new Response("bad signature", { status: 400 }); }
  const upsert = async (sub: Stripe.Subscription, uid: string) =>
    admin.from("subscriptions").upsert({
      user_id: uid, status: sub.status, provider: "stripe", provider_customer_id: String(sub.customer),
      provider_sub_id: sub.id, current_period_end: new Date(sub.current_period_end * 1000).toISOString(), updated_at: new Date().toISOString(),
    });
  if (ev.type === "checkout.session.completed") {
    const s = ev.data.object as Stripe.Checkout.Session;
    if (s.mode === "subscription" && s.client_reference_id && s.subscription)
      await upsert(await stripe.subscriptions.retrieve(String(s.subscription)), s.client_reference_id);
  } else if (ev.type === "customer.subscription.updated" || ev.type === "customer.subscription.deleted") {
    const sub = ev.data.object as Stripe.Subscription;
    const { data } = await admin.from("subscriptions").select("user_id").eq("provider_sub_id", sub.id).maybeSingle();
    if (data) await upsert(sub, data.user_id);
  }
  return new Response("ok");
});
