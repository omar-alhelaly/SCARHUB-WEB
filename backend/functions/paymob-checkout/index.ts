// UNTESTED. Starts a Paymob payment for the signed-in user. Price comes from the plans table, never from the client.
// Needs Edge Function secrets (set in Supabase, never in the repo): PAYMOB_SECRET_KEY, PAYMOB_PUBLIC_KEY, PAYMOB_INTEGRATION_ID.
import { createClient } from "npm:@supabase/supabase-js@2";
import { cors, json, ORIGIN } from "../_shared/cors.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  const url = Deno.env.get("SUPABASE_URL")!;
  const sb = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } });
  const { data: { user } } = await sb.auth.getUser();
  if (!user) return json({ error: "auth" }, 401);
  const { plan_id } = await req.json().catch(() => ({}));
  if (typeof plan_id !== "string") return json({ error: "plan" }, 400);
  const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  // paymob_start checks: active account, Paymob switched on by the owner, active EGP plan. It records the price.
  const { data, error } = await admin.rpc("paymob_start", { p_user: user.id, p_plan: plan_id });
  const row = Array.isArray(data) ? data[0] : data;
  if (error || !row) return json({ error: "unavailable" }, 400);
  const r = await fetch("https://accept.paymob.com/v1/intention/", {
    method: "POST",
    headers: { Authorization: `Token ${Deno.env.get("PAYMOB_SECRET_KEY")}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      amount: row.amount_minor, currency: row.currency, payment_methods: [Number(Deno.env.get("PAYMOB_INTEGRATION_ID"))],
      items: [{ name: "SCARHUB subscription", amount: row.amount_minor, description: "SCARHUB subscription", quantity: 1 }],
      billing_data: { first_name: "SCARHUB", last_name: "Customer", email: user.email, phone_number: "NA", apartment: "NA", floor: "NA", street: "NA", building: "NA", shipping_method: "NA", postal_code: "NA", city: "NA", country: "EG", state: "NA" },
      special_reference: row.request_id,
      notification_url: `${url}/functions/v1/paymob-webhook`,
      redirection_url: `${ORIGIN}/SCARHUB-WEB/account.html?sub=paymob`,
    }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.client_secret) return json({ error: "provider" }, 502);
  const checkout = `https://eg.checkout.paymob.com/?publicKey=${encodeURIComponent(Deno.env.get("PAYMOB_PUBLIC_KEY")!)}&clientSecret=${encodeURIComponent(j.client_secret)}`;
  return json({ url: checkout });
});
