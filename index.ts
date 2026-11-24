// Self-service delete: requires a fresh password re-check, keeps a 'deleted' row for admins, removes the auth login.
import { createClient } from "npm:@supabase/supabase-js@2";
import { cors, json } from "../_shared/cors.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  const url = Deno.env.get("SUPABASE_URL")!;
  const sb = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } });
  const { data: { user } } = await sb.auth.getUser();
  if (!user) return json({ error: "auth" }, 401);
  const { password } = await req.json().catch(() => ({}));
  if (typeof password !== "string") return json({ error: "password" }, 400);
  const probe = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!);
  const { error: pe } = await probe.auth.signInWithPassword({ email: user.email!, password });
  if (pe) return json({ error: "wrong password" }, 403);
  const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const { error } = await admin.rpc("mark_deleted", { uid: user.id });
  if (error) return json({ error: "cannot delete" }, 403);
  await admin.auth.admin.deleteUser(user.id);
  return json({ ok: true });
});
