-- Rozpočet Balínkovi – databázové schéma pro Supabase
-- Všechna data domácnosti jsou šifrovaná v telefonu (AES-256-GCM). Server vidí jen nečitelné bloky.
-- Spuštění: Supabase → SQL Editor → vložit celý soubor → Run. Skript jde spustit opakovaně.

create extension if not exists pgcrypto with schema extensions;

-- Domácnost: kód pro připojení, sůl pro odvození klíče a otisk přístupového tokenu (ne heslo, ne klíč)
create table if not exists public.households (
  id uuid primary key default gen_random_uuid(),
  code text unique not null,
  salt text not null,
  join_hash text not null,
  created_at timestamptz not null default now()
);

-- Členové: anonymní uživatelé (telefony), kteří znají heslo domácnosti
create table if not exists public.members (
  household_id uuid not null references public.households(id) on delete cascade,
  user_id uuid not null default auth.uid(),
  created_at timestamptz not null default now(),
  primary key (household_id, user_id)
);

-- Záznamy: každý pohyb, fix, cíl, účet… jako šifrovaný blok
create table if not exists public.records (
  household_id uuid not null references public.households(id) on delete cascade,
  kind text not null,
  id text not null,
  iv text,
  ct text,
  deleted boolean not null default false,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid(),
  primary key (household_id, kind, id)
);
create index if not exists records_sync_idx on public.records (household_id, updated_at);

alter table public.households enable row level security;
alter table public.members enable row level security;
alter table public.records enable row level security;

create or replace function public.is_member(h uuid) returns boolean
language sql security definer stable set search_path = '' as $$
  select exists (select 1 from public.members m where m.household_id = h and m.user_id = auth.uid())
$$;

drop policy if exists "hh read" on public.households;
create policy "hh read" on public.households for select to authenticated using (public.is_member(id));

drop policy if exists "members read" on public.members;
create policy "members read" on public.members for select to authenticated using (public.is_member(household_id));
drop policy if exists "members leave" on public.members;
create policy "members leave" on public.members for delete to authenticated using (user_id = auth.uid());

drop policy if exists "rec read" on public.records;
create policy "rec read" on public.records for select to authenticated using (public.is_member(household_id));
drop policy if exists "rec insert" on public.records;
create policy "rec insert" on public.records for insert to authenticated with check (public.is_member(household_id));
drop policy if exists "rec update" on public.records;
create policy "rec update" on public.records for update to authenticated using (public.is_member(household_id)) with check (public.is_member(household_id));

-- Čas a autor změny nastavuje server
create or replace function public.records_touch() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.updated_at := clock_timestamp();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists records_touch on public.records;
create trigger records_touch before insert or update on public.records
for each row execute function public.records_touch();

-- Založení domácnosti
create or replace function public.create_household(p_salt text, p_token text)
returns table (household_id uuid, household_code text)
language plpgsql security definer set search_path = '' as $$
declare h uuid; c text;
begin
  if auth.uid() is null then raise exception 'Nejste přihlášeni'; end if;
  if length(p_token) < 32 then raise exception 'Neplatný token'; end if;
  loop
    c := upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8));
    exit when not exists (select 1 from public.households x where x.code = c);
  end loop;
  insert into public.households (code, salt, join_hash)
    values (c, p_salt, encode(extensions.digest(p_token, 'sha256'), 'hex'))
    returning id into h;
  insert into public.members (household_id, user_id) values (h, auth.uid());
  return query select h, c;
end $$;

-- Sůl podle kódu (potřeba k odvození klíče z hesla při připojení)
create or replace function public.household_salt(p_code text) returns text
language sql security definer stable set search_path = '' as $$
  select salt from public.households where code = upper(trim(p_code))
$$;

-- Připojení dalšího telefonu: projde jen se správným heslem (ověřuje se otisk tokenu)
create or replace function public.join_household(p_code text, p_token text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare h uuid;
begin
  if auth.uid() is null then raise exception 'Nejste přihlášeni'; end if;
  select id into h from public.households
    where code = upper(trim(p_code)) and join_hash = encode(extensions.digest(p_token, 'sha256'), 'hex');
  if h is null then raise exception 'Špatný kód nebo heslo'; end if;
  insert into public.members (household_id, user_id) values (h, auth.uid()) on conflict do nothing;
  return h;
end $$;

revoke all on function public.create_household(text, text) from public, anon;
revoke all on function public.household_salt(text) from public, anon;
revoke all on function public.join_household(text, text) from public, anon;
grant execute on function public.create_household(text, text) to authenticated;
grant execute on function public.household_salt(text) to authenticated;
grant execute on function public.join_household(text, text) to authenticated;

-- Živá synchronizace mezi telefony
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'records') then
    alter publication supabase_realtime add table public.records;
  end if;
end $$;

-- Utažení oprávnění: anonymní (nepřihlášený) klíč k tabulkám nemá přístup vůbec
revoke all on public.households, public.members, public.records from anon;
revoke insert, update, delete, truncate, references, trigger on public.households from authenticated;
revoke insert, update, truncate, references, trigger on public.members from authenticated;
revoke delete, truncate, references, trigger on public.records from authenticated;
