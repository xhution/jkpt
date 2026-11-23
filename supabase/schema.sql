-- JoachimKantola PT: databas för inloggning, träning och lag
-- Klistra in allt i Supabase → SQL Editor → Run. Kan köras flera gånger.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  name text,
  role text not null default 'client' check (role in ('admin','coach','client')),
  created_at timestamptz not null default now()
);
create table if not exists public.user_state (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
create table if not exists public.workouts (
  user_id uuid not null references auth.users(id) on delete cascade,
  id text not null,
  date timestamptz not null,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (user_id, id)
);
create table if not exists public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner uuid not null default auth.uid() references auth.users(id) on delete cascade,
  join_code text not null unique default upper(substr(md5(random()::text), 1, 6)),
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create table if not exists public.team_members (
  team_id uuid not null references public.teams(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'coach' check (role in ('owner','coach')),
  joined_at timestamptz not null default now(),
  primary key (team_id, user_id)
);
create table if not exists public.team_sessions (
  team_id uuid not null references public.teams(id) on delete cascade,
  id text not null,
  date date,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid(),
  primary key (team_id, id)
);

-- Hjälpfunktioner (security definer undviker rundgång i reglerna)
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin')
$$;
create or replace function public.is_team_member(t uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from team_members where team_id = t and user_id = auth.uid())
$$;
create or replace function public.is_team_owner(t uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from team_members where team_id = t and user_id = auth.uid() and role = 'owner')
$$;

-- Ny användare får en profil. Den allra första blir admin.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, email, name, role, created_at)
  values (new.id, new.email, split_part(new.email, '@', 1),
          case when exists (select 1 from profiles) then 'client' else 'admin' end, now())
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Användare som redan finns får profil; äldsta blir admin om ingen admin finns
insert into public.profiles (id, email, name, role, created_at)
  select id, email, split_part(email, '@', 1), 'client', created_at from auth.users
  on conflict (id) do nothing;
update public.profiles set role = 'admin'
  where id = (select id from public.profiles order by created_at limit 1)
  and not exists (select 1 from public.profiles where role = 'admin');

-- Den som skapar ett lag blir dess ägare
create or replace function public.handle_new_team() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into team_members (team_id, user_id, role) values (new.id, new.owner, 'owner')
  on conflict do nothing;
  return new;
end $$;
drop trigger if exists on_team_created on public.teams;
create trigger on_team_created after insert on public.teams
  for each row execute function public.handle_new_team();

-- Gå med i ett lag med kod
create or replace function public.join_team(code text) returns uuid
language plpgsql security definer set search_path = public as $$
declare t uuid;
begin
  if auth.uid() is null then raise exception 'Inte inloggad'; end if;
  select id into t from teams where join_code = upper(trim(code));
  if t is null then raise exception 'Ingen lag med den koden'; end if;
  insert into team_members (team_id, user_id, role) values (t, auth.uid(), 'coach')
  on conflict do nothing;
  return t;
end $$;

-- Ny lagkod (bara ägaren)
create or replace function public.new_join_code(t uuid) returns text
language plpgsql security definer set search_path = public as $$
declare c text;
begin
  if not is_team_owner(t) then raise exception 'Bara lagets ägare kan byta kod'; end if;
  c := upper(substr(md5(random()::text), 1, 6));
  update teams set join_code = c where id = t;
  return c;
end $$;

-- Lagets tränare med namn och e-post (bara för medlemmar)
create or replace function public.team_people(t uuid)
returns table (user_id uuid, name text, email text, role text)
language sql stable security definer set search_path = public as $$
  select m.user_id, p.name, p.email, m.role
  from team_members m left join profiles p on p.id = m.user_id
  where m.team_id = t and is_team_member(t)
  order by m.role desc, p.name
$$;

-- Adminens klientlista
create or replace function public.admin_clients()
returns table (id uuid, name text, email text, role text, last_workout timestamptz, n30 bigint, total bigint)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.email, p.role,
         max(w.date), count(w.id) filter (where w.date > now() - interval '30 days'), count(w.id)
  from profiles p left join workouts w on w.user_id = p.id
  where is_admin() and p.id <> auth.uid()
  group by p.id order by max(w.date) desc nulls last
$$;

-- Säkerhetsregler: varje rad skyddas
alter table public.profiles enable row level security;
alter table public.user_state enable row level security;
alter table public.workouts enable row level security;
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.team_sessions enable row level security;

drop policy if exists "profil läs" on public.profiles;
create policy "profil läs" on public.profiles for select to authenticated using (id = auth.uid() or is_admin());
drop policy if exists "profil ändra" on public.profiles;
create policy "profil ändra" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists "egen data" on public.user_state;
create policy "egen data" on public.user_state for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "admin läser data" on public.user_state;
create policy "admin läser data" on public.user_state for select to authenticated using (is_admin());

drop policy if exists "egna pass" on public.workouts;
create policy "egna pass" on public.workouts for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "admin läser pass" on public.workouts;
create policy "admin läser pass" on public.workouts for select to authenticated using (is_admin());

drop policy if exists "lag läs" on public.teams;
create policy "lag läs" on public.teams for select to authenticated using (is_team_member(id));
drop policy if exists "lag skapa" on public.teams;
create policy "lag skapa" on public.teams for insert to authenticated with check (is_admin() and owner = auth.uid());
drop policy if exists "lag ändra" on public.teams;
create policy "lag ändra" on public.teams for update to authenticated using (is_team_member(id)) with check (is_team_member(id));
drop policy if exists "lag radera" on public.teams;
create policy "lag radera" on public.teams for delete to authenticated using (owner = auth.uid());

drop policy if exists "medlem läs" on public.team_members;
create policy "medlem läs" on public.team_members for select to authenticated using (is_team_member(team_id));
drop policy if exists "medlem ta bort" on public.team_members;
create policy "medlem ta bort" on public.team_members for delete to authenticated
  using ((is_team_owner(team_id) and role <> 'owner') or (user_id = auth.uid() and role <> 'owner'));

drop policy if exists "lagpass" on public.team_sessions;
create policy "lagpass" on public.team_sessions for all to authenticated using (is_team_member(team_id)) with check (is_team_member(team_id));

-- Behörigheter för appen (inget för utloggade)
grant usage on schema public to authenticated;
grant select on public.profiles to authenticated;
grant update (name) on public.profiles to authenticated;
grant select, insert, update, delete on public.user_state, public.workouts, public.team_sessions to authenticated;
grant select, delete on public.teams to authenticated;
grant insert (name, data) on public.teams to authenticated;
grant update (name, data, updated_at) on public.teams to authenticated;
grant select, delete on public.team_members to authenticated;
grant execute on function public.is_admin(), public.is_team_member(uuid), public.is_team_owner(uuid),
  public.join_team(text), public.new_join_code(uuid), public.team_people(uuid), public.admin_clients() to authenticated;
revoke execute on function public.join_team(text), public.new_join_code(uuid), public.team_people(uuid), public.admin_clients() from anon, public;
