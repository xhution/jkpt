-- JoachimKantola PT, del 2: inbjudningar och roller
-- Klistra in allt i Supabase → SQL Editor → Run.

create table if not exists public.invites (
  code text primary key,
  role text not null default 'client' check (role in ('admin','coach','client')),
  note text,
  created_by uuid default auth.uid() references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  used_by uuid references auth.users(id) on delete set null,
  used_at timestamptz
);
alter table public.invites enable row level security;
drop policy if exists "admin inbjudningar" on public.invites;
create policy "admin inbjudningar" on public.invites for all to authenticated using (is_admin()) with check (is_admin());
grant select, insert, delete on public.invites to authenticated;

-- Nya konton: första blir admin, annars krävs en giltig inbjudningskod
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare inv record; r text;
begin
  if not exists (select 1 from profiles) then
    r := 'admin';
  else
    select * into inv from invites
      where code = upper(trim(coalesce(new.raw_user_meta_data->>'invite', ''))) and used_by is null;
    if inv.code is null then
      raise exception 'Ogiltig eller använd inbjudningskod';
    end if;
    r := inv.role;
    update invites set used_by = new.id, used_at = now() where code = inv.code;
  end if;
  insert into profiles (id, email, name, role, created_at)
  values (new.id, new.email,
          coalesce(nullif(new.raw_user_meta_data->>'name', ''), split_part(new.email, '@', 1)), r, now())
  on conflict (id) do nothing;
  return new;
end $$;

-- Admin ändrar roll (den sista adminen kan inte tas bort)
create or replace function public.set_role(uid uuid, new_role text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Bara admin kan ändra roller'; end if;
  if new_role not in ('admin','coach','client') then raise exception 'Okänd roll'; end if;
  if new_role <> 'admin' and (select role from profiles where id = uid) = 'admin'
     and (select count(*) from profiles where role = 'admin') <= 1 then
    raise exception 'Det måste finnas minst en admin';
  end if;
  update profiles set role = new_role where id = uid;
end $$;

-- Tränare och admin får skapa lag
create or replace function public.is_coach() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role in ('admin','coach'))
$$;
drop policy if exists "lag skapa" on public.teams;
create policy "lag skapa" on public.teams for insert to authenticated with check (is_coach() and owner = auth.uid());

-- Adminens lista över alla användare
drop function if exists public.admin_clients();
create or replace function public.admin_clients()
returns table (id uuid, name text, email text, role text, last_workout timestamptz, n30 bigint, total bigint)
language sql stable security definer set search_path = public as $$
  select p.id, p.name, p.email, p.role,
         max(w.date), count(w.id) filter (where w.date > now() - interval '30 days'), count(w.id)
  from profiles p left join workouts w on w.user_id = p.id
  where is_admin()
  group by p.id order by p.role, p.name
$$;

grant execute on function public.set_role(uuid, text), public.is_coach(), public.admin_clients() to authenticated;
revoke execute on function public.set_role(uuid, text), public.admin_clients() from anon, public;
