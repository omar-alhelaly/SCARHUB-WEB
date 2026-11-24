// Creates a Stripe Checkout session for the signed-in user. Price comes from server env, never from the client.
import { createClient } from "npm:@supabase/supabase-js@2";
import Stripe from "npm:stripe@16";
import { cors, json, ORIGIN } from "../_shared/cors.ts";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
  });
  const { data: { user } } = await sb.auth.getUser();
  if (!user) return json({ error: "auth" }, 401);
  const { data: prof } = await sb.from("profiles").select("status").eq("id", user.id).single();
  if (prof?.status !== "active") return json({ error: "forbidden" }, 403);
  // Price comes from the owner-managed plans table (server-side lookup), never from the request.
  const { plan_id } = await req.json().catch(() => ({}));
  const { data: plan } = await sb.from("plans").select("provider, provider_ref, active").eq("id", plan_id ?? "").maybeSingle();
  if (!plan || !plan.active || plan.provider !== "stripe" || !plan.provider_ref) return json({ error: "plan" }, 400);
  const s = await stripe.checkout.sessions.create({
    mode: "subscription",
    line_items: [{ price: plan.provider_ref, quantity: 1 }],
    client_reference_id: user.id,
    customer_email: user.email!,
    success_url: `${ORIGIN}/SCARHUB-WEB/account.html?sub=ok`,
    cancel_url: `${ORIGIN}/SCARHUB-WEB/account.html?sub=cancel`,
  });
  return json({ url: s.url });
});
