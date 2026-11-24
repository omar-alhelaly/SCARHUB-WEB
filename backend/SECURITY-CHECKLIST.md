# SCARHUB security checklist (for Omar and his pentesters)

Honest scope: the site is static on GitHub Pages. Real protection lives in Supabase (RLS, Auth, Edge Functions). Hiding the admin page URL is NOT security; the database policies are.

## Design
- Roles: owner (one, set from owner_email on first signup), admin, user. Role changes only via `set_role` (owner only), audit logged.
- Role is never read from client data or user metadata. All tables have RLS on; clients have no direct write grant on profiles/subscriptions/audit.
- Staff show an alias everywhere. `public_profiles` and chat use alias for staff. Only the owner sees staff usernames (admin_list_users).
- Private tool assets: RLS + private storage bucket; subscription state is written only by the signature-verified Stripe webhook.
- One account per normalized email (case, +tags, gmail dots). One per real person cannot be enforced technically.
- Deleted accounts keep a profile row (status=deleted) so admins see them; auth login is removed. Owner cannot be deleted.
- Chat: length limit, rate limit trigger, text only (rendered with textContent, never innerHTML).

## Supabase dashboard settings (must be set by the project owner)
1. Auth > Email: enable "Confirm email" with OTP code. Disable other providers unless needed.
2. Auth > Password: minimum length 12, require letters, digits, symbols. Leak protection ON (Pro plan).
3. Auth > Rate limits: keep defaults or lower; enable CAPTCHA (hCaptcha/Turnstile) for sign-up and sign-in.
4. Auth > URL config: Site URL = https://omar-alhelaly.github.io/SCARHUB-WEB/ and only that redirect URL.
5. API: expose only the `public` schema. Never put the service_role key in any file in the repo.
6. Enable MFA (TOTP) for the owner and admins; the admin UI warns if not enrolled.
7. Edge Function secrets: SITE_ORIGIN, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET. Deploy stripe-webhook with --no-verify-jwt (it verifies Stripe signature itself).

## Front end
- Strict CSP meta tag on auth pages, no inline scripts, no third-party scripts except supabase-js from a pinned, SRI-checked file.
- All user text via textContent. Validation on the client is for UX only; the same rules are enforced by DB constraints.

## Things pentesters should try (expected: all denied)
- Insert/update profiles.role via REST. Read another user's profile, email, subscription.
- Read tool_assets of a private tool without subscription; read storage objects directly.
- Write to admins chat as a user; read it as a user. Delete others' messages as a user.
- Call set_role as admin. Call mark_deleted as authenticated. Replay a webhook without valid signature.
- Sign up with `a+1@gmail.com` after `a@gmail.com`.

## Known limits
- Egypt: Stripe may not onboard Egyptian merchants directly; a local provider (Paymob/Fawry) needs a different webhook function.
- Password policy: 12-64 chars, letters + digits + symbols (agreed with Omar; replaces the first 5-12 idea).
- Paymob, Fawry and PayPal are configurable in the plans table, but only Stripe has a checkout + webhook function so far. Each other provider needs its own signed-webhook function and merchant account before it can be switched on.
- ALL money features (plans, prices, provider switches, subscription records, subscriber flags) are owner-only in RLS/RPCs. Admins get no read or write access. Any refunds or payouts are done in the payment provider dashboard by the owner.
