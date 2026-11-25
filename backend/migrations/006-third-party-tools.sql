alter table public.tools
  add column third_party boolean not null default false,
  add column orig_creator text check (orig_creator is null or char_length(orig_creator) between 2 and 80),
  add column orig_license text check (orig_license is null or char_length(orig_license) between 2 and 60),
  add column orig_repo text check (orig_repo is null or orig_repo ~ '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
  add constraint tools_third_party_credit check (not third_party or (orig_creator is not null and orig_license is not null and orig_repo is not null));
