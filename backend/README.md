# SCARHUB backend (disabled, untested)

Status: code only. Nothing here has been run against a real Supabase project or Stripe account. Accounts and payments stay switched off until config.js is filled in, and that must not happen before the activation gates below are met.

Contents: `schema.sql` (tables, RLS, RPCs), `functions/` (Edge Functions), `SECURITY-CHECKLIST.md`.

## Activation gates
1. Run `schema.sql` on a fresh Supabase project and fix any errors. It has only been parsed, never executed.
2. Run the pentest cases in SECURITY-CHECKLIST.md against it, and fix what fails.
3. Set the Auth options in the checklist (email OTP, password length 12, CAPTCHA, redirect URL).
4. Owner bootstrap: sign up, verify the email, then run `select public.claim_owner('<user id>');` once in the SQL editor. No owner email is stored in the repo.
5. Deploy the Edge Functions with their secrets. Test a Stripe test-mode payment, a replayed webhook and a failed DB write before using live keys.
6. Only then fill `config.js`.
