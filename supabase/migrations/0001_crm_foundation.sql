-- iFranchise CRM foundation schema
--
-- Identity and tenancy only. No operational CRM entities yet.
--
-- Concept map:
--   Organization            -> public.organizations
--   Brand                   -> public.brands
--   User/Profile            -> public.profiles (1:1 with auth.users)
--   Roles                   -> public.roles
--   User <-> Organization   -> public.organization_memberships
--   User <-> Brand access   -> public.brand_memberships
--
-- Authorization model:
--   CEO / TL / Admin  -> organization-scoped membership; broader access to that org
--   Brand Owner       -> brand-scoped membership; assigned brands only
--   auth.uid() is the only caller identity used by RLS helpers. Client-supplied
--   organization_id / brand_id values are never trusted on their own.
--   Archived profiles cannot satisfy authorization checks.

-- ---------------------------------------------------------------------------
-- Types
-- ---------------------------------------------------------------------------

create type public.access_scope as enum ('organization', 'brand');

comment on type public.access_scope is
  'Whether a role applies to an organization or to a specific brand.';

-- ---------------------------------------------------------------------------
-- Shared trigger: updated_at
-- ---------------------------------------------------------------------------

create function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

comment on function public.set_updated_at() is
  'Keeps updated_at current on row changes.';

-- ---------------------------------------------------------------------------
-- organizations
-- ---------------------------------------------------------------------------

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint organizations_name_not_blank_chk
    check (char_length(trim(name)) > 0),
  constraint organizations_slug_format_chk
    check (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$')
);

comment on table public.organizations is
  'Top-level business/company tenant.';

create unique index organizations_slug_active_key
  on public.organizations (slug)
  where archived_at is null;

create trigger organizations_set_updated_at
  before update on public.organizations
  for each row
  execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- roles
-- ---------------------------------------------------------------------------

create table public.roles (
  id uuid primary key default gen_random_uuid(),
  code text not null,
  name text not null,
  description text,
  scope public.access_scope not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint roles_code_format_chk
    check (code ~ '^[a-z][a-z0-9_]*$'),
  constraint roles_name_not_blank_chk
    check (char_length(trim(name)) > 0),
  constraint roles_code_key unique (code),
  constraint roles_id_scope_key unique (id, scope)
);

comment on table public.roles is
  'Controlled CRM role catalog. Add future roles as rows; do not overload enums.';

comment on column public.roles.scope is
  'Prevents assigning a brand role to an organization membership and vice versa.';

create index roles_scope_idx on public.roles (scope);

create trigger roles_set_updated_at
  before update on public.roles
  for each row
  execute function public.set_updated_at();

insert into public.roles (code, name, description, scope)
values
  (
    'ceo',
    'CEO',
    'Organization-wide executive access.',
    'organization'
  ),
  (
    'tl',
    'TL',
    'Organization-wide team-lead access. Broader than brand-scoped roles; cannot administer organization settings.',
    'organization'
  ),
  (
    'admin',
    'Admin',
    'Organization-wide administrative access.',
    'organization'
  ),
  (
    'brand_owner',
    'Brand Owner',
    'Access limited to explicitly assigned brands.',
    'brand'
  );

-- ---------------------------------------------------------------------------
-- brands
-- ---------------------------------------------------------------------------

create table public.brands (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete restrict,
  name text not null,
  slug text not null,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint brands_name_not_blank_chk
    check (char_length(trim(name)) > 0),
  constraint brands_slug_format_chk
    check (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$')
);

comment on table public.brands is
  'Brand belonging to an organization. Future CRM records should hang off brand_id.';

create index brands_organization_id_idx
  on public.brands (organization_id);

create unique index brands_organization_slug_active_key
  on public.brands (organization_id, slug)
  where archived_at is null;

create unique index brands_organization_name_active_key
  on public.brands (organization_id, lower(trim(name)))
  where archived_at is null;

create trigger brands_set_updated_at
  before update on public.brands
  for each row
  execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- profiles
-- ---------------------------------------------------------------------------

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  full_name text,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.profiles is
  'Application profile for an Auth user. Tenancy is expressed via memberships, not a client-owned org/brand column.';

create unique index profiles_email_key
  on public.profiles (email)
  where email is not null;

create trigger profiles_set_updated_at
  before update on public.profiles
  for each row
  execute function public.set_updated_at();

create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    new.email,
    nullif(
      trim(
        coalesce(
          new.raw_user_meta_data ->> 'full_name',
          new.raw_user_meta_data ->> 'name',
          ''
        )
      ),
      ''
    )
  );
  return new;
end;
$$;

comment on function public.handle_new_user() is
  'Creates a public.profiles row when a new auth.users row is inserted.';

create trigger on_auth_user_created
  after insert on auth.users
  for each row
  execute function public.handle_new_user();

create function public.sync_profile_email()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.profiles
  set email = new.email
  where id = new.id;
  return new;
end;
$$;

comment on function public.sync_profile_email() is
  'Keeps profiles.email aligned with auth.users.email.';

create trigger on_auth_user_email_updated
  after update of email on auth.users
  for each row
  when (old.email is distinct from new.email)
  execute function public.sync_profile_email();

-- ---------------------------------------------------------------------------
-- organization_memberships
-- ---------------------------------------------------------------------------

create table public.organization_memberships (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  role_id uuid not null,
  role_scope public.access_scope generated always as ('organization'::public.access_scope) stored,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint organization_memberships_user_org_key unique (organization_id, user_id),
  constraint organization_memberships_role_scope_fkey
    foreign key (role_id, role_scope) references public.roles (id, scope)
);

comment on table public.organization_memberships is
  'Organization-level RBAC assignment. CEO, TL, and Admin live here.';

create index organization_memberships_user_id_idx
  on public.organization_memberships (user_id);

create index organization_memberships_role_id_idx
  on public.organization_memberships (role_id);

create index organization_memberships_active_org_user_idx
  on public.organization_memberships (organization_id, user_id)
  where archived_at is null;

create trigger organization_memberships_set_updated_at
  before update on public.organization_memberships
  for each row
  execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- brand_memberships
-- ---------------------------------------------------------------------------

create table public.brand_memberships (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  role_id uuid not null,
  role_scope public.access_scope generated always as ('brand'::public.access_scope) stored,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint brand_memberships_user_brand_key unique (brand_id, user_id),
  constraint brand_memberships_role_scope_fkey
    foreign key (role_id, role_scope) references public.roles (id, scope)
);

comment on table public.brand_memberships is
  'Brand-level RBAC assignment. Brand owners must be associated with specific brands here.';

create index brand_memberships_user_id_idx
  on public.brand_memberships (user_id);

create index brand_memberships_role_id_idx
  on public.brand_memberships (role_id);

create index brand_memberships_active_brand_user_idx
  on public.brand_memberships (brand_id, user_id)
  where archived_at is null;

create trigger brand_memberships_set_updated_at
  before update on public.brand_memberships
  for each row
  execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- Authorization helpers
--
-- SECURITY DEFINER is required so RLS policies can inspect memberships without
-- recursion. Functions always key off auth.uid(), never a client-supplied user id
-- for the current principal. search_path is pinned empty to prevent hijacking.
-- ---------------------------------------------------------------------------

create function public.current_user_is_active()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles as p
    where p.id = (select auth.uid())
      and p.archived_at is null
  );
$$;

comment on function public.current_user_is_active() is
  'True when the current Auth user has a non-archived profile. Archived users must not pass RLS.';

create function public.is_org_active(p_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.organizations as o
    where o.id = p_organization_id
      and o.archived_at is null
  );
$$;

comment on function public.is_org_active(uuid) is
  'True when the organization exists and is not archived.';

create function public.is_org_reader(p_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    public.current_user_is_active()
    and exists (
      select 1
      from public.organization_memberships as om
      join public.roles as r on r.id = om.role_id
      where om.organization_id = p_organization_id
        and om.user_id = (select auth.uid())
        and om.archived_at is null
        and r.scope = 'organization'::public.access_scope
        and r.code in ('ceo', 'tl', 'admin')
    );
$$;

comment on function public.is_org_reader(uuid) is
  'True when the current user has CEO, TL, or Admin membership in the organization.';

create function public.is_org_admin(p_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    public.current_user_is_active()
    and exists (
      select 1
      from public.organization_memberships as om
      join public.roles as r on r.id = om.role_id
      where om.organization_id = p_organization_id
        and om.user_id = (select auth.uid())
        and om.archived_at is null
        and r.scope = 'organization'::public.access_scope
        and r.code in ('ceo', 'admin')
    );
$$;

comment on function public.is_org_admin(uuid) is
  'True when the current user can administer organization settings, brands, and memberships (CEO or Admin).';

create function public.has_org_visibility(p_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    public.current_user_is_active()
    and (
      public.is_org_reader(p_organization_id)
      or exists (
        select 1
        from public.organization_memberships as om
        where om.organization_id = p_organization_id
          and om.user_id = (select auth.uid())
          and om.archived_at is null
      )
      or exists (
        select 1
        from public.brand_memberships as bm
        join public.brands as b on b.id = bm.brand_id
        where b.organization_id = p_organization_id
          and bm.user_id = (select auth.uid())
          and bm.archived_at is null
          and b.archived_at is null
      )
    );
$$;

comment on function public.has_org_visibility(uuid) is
  'True when the current user may see the organization record (org membership or an active brand assignment in that org).';

create function public.is_brand_member(p_brand_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    public.current_user_is_active()
    and exists (
      select 1
      from public.brand_memberships as bm
      where bm.brand_id = p_brand_id
        and bm.user_id = (select auth.uid())
        and bm.archived_at is null
    );
$$;

comment on function public.is_brand_member(uuid) is
  'True when the current user has an active membership on the brand.';

create function public.has_brand_access(p_brand_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    public.current_user_is_active()
    and exists (
      select 1
      from public.brands as b
      join public.organizations as o on o.id = b.organization_id
      where b.id = p_brand_id
        and (
          public.is_org_reader(b.organization_id)
          or (
            public.is_brand_member(b.id)
            and b.archived_at is null
            and o.archived_at is null
          )
        )
    );
$$;

comment on function public.has_brand_access(uuid) is
  'Primary future RLS helper for brand-scoped CRM tables. Org readers see all brands in their org; brand-scoped users see assigned active brands only. Client-supplied brand_id is not trusted unless membership/org-role checks pass.';

create function public.can_admin_brand(p_brand_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.brands as b
    where b.id = p_brand_id
      and public.is_org_admin(b.organization_id)
  );
$$;

comment on function public.can_admin_brand(uuid) is
  'True when the current user can mutate a brand or existing memberships, including archived brands they still administer.';

create function public.can_assign_brand_access(p_brand_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.brands as b
    join public.organizations as o on o.id = b.organization_id
    where b.id = p_brand_id
      and b.archived_at is null
      and o.archived_at is null
      and public.is_org_admin(b.organization_id)
  );
$$;

comment on function public.can_assign_brand_access(uuid) is
  'True when the current user may grant brand membership on an active brand in an active organization.';

create function public.can_read_profile(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    public.current_user_is_active()
    and (
      exists (
        select 1
        from public.organization_memberships as target
        where target.user_id = p_user_id
          and target.archived_at is null
          and public.is_org_reader(target.organization_id)
      )
      or exists (
        select 1
        from public.brand_memberships as them
        join public.brands as b on b.id = them.brand_id
        where them.user_id = p_user_id
          and them.archived_at is null
          and b.archived_at is null
          and public.is_org_reader(b.organization_id)
      )
      or exists (
        select 1
        from public.brand_memberships as me
        join public.brand_memberships as them on them.brand_id = me.brand_id
        join public.brands as b on b.id = me.brand_id
        where me.user_id = (select auth.uid())
          and them.user_id = p_user_id
          and me.archived_at is null
          and them.archived_at is null
          and b.archived_at is null
      )
    );
$$;

comment on function public.can_read_profile(uuid) is
  'True when the current user may read another profile in a shared org or active brand.';

create function public.can_admin_profile(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select
    public.current_user_is_active()
    and (select auth.uid()) is distinct from p_user_id
    and (
      exists (
        select 1
        from public.organization_memberships as target
        where target.user_id = p_user_id
          and target.archived_at is null
          and public.is_org_admin(target.organization_id)
      )
      or exists (
        select 1
        from public.brand_memberships as them
        join public.brands as b on b.id = them.brand_id
        where them.user_id = p_user_id
          and them.archived_at is null
          and public.is_org_admin(b.organization_id)
      )
    );
$$;

comment on function public.can_admin_profile(uuid) is
  'True when the current user may administer another profile in their organization. Users cannot administer themselves.';

create function public.protect_profile_row()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.id is distinct from old.id then
    raise exception 'profiles.id is immutable';
  end if;

  -- Email is owned by Auth. Nested updates from sync_profile_email are allowed.
  if new.email is distinct from old.email and pg_trigger_depth() < 2 then
    raise exception 'profiles.email is managed by auth.users';
  end if;

  if new.archived_at is distinct from old.archived_at then
    if not public.can_admin_profile(old.id) then
      raise exception 'not allowed to change profile archive state';
    end if;
  end if;

  return new;
end;
$$;

comment on function public.protect_profile_row() is
  'Prevents identity swap, client-controlled email changes, and self-unarchive.';

create trigger profiles_protect_row
  before update on public.profiles
  for each row
  execute function public.protect_profile_row();

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------

alter table public.organizations enable row level security;
alter table public.organizations force row level security;

alter table public.roles enable row level security;
alter table public.roles force row level security;

alter table public.brands enable row level security;
alter table public.brands force row level security;

alter table public.profiles enable row level security;
alter table public.profiles force row level security;

alter table public.organization_memberships enable row level security;
alter table public.organization_memberships force row level security;

alter table public.brand_memberships enable row level security;
alter table public.brand_memberships force row level security;

-- roles: catalog is not sensitive CRM data; authenticated users need it for RBAC UI.
create policy roles_select_authenticated
  on public.roles
  for select
  to authenticated
  using (true);

-- organizations
create policy organizations_select_visible
  on public.organizations
  for select
  to authenticated
  using (public.has_org_visibility(id));

create policy organizations_update_admin
  on public.organizations
  for update
  to authenticated
  using (public.is_org_admin(id))
  with check (public.is_org_admin(id));

-- brands
create policy brands_select_accessible
  on public.brands
  for select
  to authenticated
  using (public.has_brand_access(id));

create policy brands_insert_org_admin
  on public.brands
  for insert
  to authenticated
  with check (
    public.is_org_admin(organization_id)
    and public.is_org_active(organization_id)
  );

create policy brands_update_org_admin
  on public.brands
  for update
  to authenticated
  using (public.can_admin_brand(id))
  with check (
    public.is_org_admin(organization_id)
    and (
      archived_at is not null
      or public.is_org_active(organization_id)
    )
  );

-- profiles
create policy profiles_select_self_or_related
  on public.profiles
  for select
  to authenticated
  using (
    id = (select auth.uid())
    or public.can_read_profile(id)
  );

create policy profiles_update_self_or_admin
  on public.profiles
  for update
  to authenticated
  using (
    id = (select auth.uid())
    or public.can_admin_profile(id)
  )
  with check (
    id = (select auth.uid())
    or public.can_admin_profile(id)
  );

-- organization_memberships
create policy organization_memberships_select_own_or_reader
  on public.organization_memberships
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or public.is_org_reader(organization_id)
  );

create policy organization_memberships_insert_org_admin
  on public.organization_memberships
  for insert
  to authenticated
  with check (
    public.is_org_admin(organization_id)
    and public.is_org_active(organization_id)
  );

create policy organization_memberships_update_org_admin
  on public.organization_memberships
  for update
  to authenticated
  using (public.is_org_admin(organization_id))
  with check (
    public.is_org_admin(organization_id)
    and (
      archived_at is not null
      or public.is_org_active(organization_id)
    )
  );

-- brand_memberships
create policy brand_memberships_select_own_or_related
  on public.brand_memberships
  for select
  to authenticated
  using (
    user_id = (select auth.uid())
    or public.has_brand_access(brand_id)
  );

create policy brand_memberships_insert_org_admin
  on public.brand_memberships
  for insert
  to authenticated
  with check (public.can_assign_brand_access(brand_id));

create policy brand_memberships_update_org_admin
  on public.brand_memberships
  for update
  to authenticated
  using (public.can_admin_brand(brand_id))
  with check (public.can_admin_brand(brand_id));

-- ---------------------------------------------------------------------------
-- Privileges
--
-- config.toml leaves auto_expose_new_tables unset, so new public objects are
-- not granted to Data API roles automatically. Grant narrowly.
-- ---------------------------------------------------------------------------

revoke all on function public.set_updated_at() from public;
revoke all on function public.handle_new_user() from public;
revoke all on function public.sync_profile_email() from public;
revoke all on function public.protect_profile_row() from public;
revoke all on function public.current_user_is_active() from public;
revoke all on function public.is_org_active(uuid) from public;
revoke all on function public.is_org_reader(uuid) from public;
revoke all on function public.is_org_admin(uuid) from public;
revoke all on function public.has_org_visibility(uuid) from public;
revoke all on function public.is_brand_member(uuid) from public;
revoke all on function public.has_brand_access(uuid) from public;
revoke all on function public.can_admin_brand(uuid) from public;
revoke all on function public.can_assign_brand_access(uuid) from public;
revoke all on function public.can_read_profile(uuid) from public;
revoke all on function public.can_admin_profile(uuid) from public;

grant execute on function public.set_updated_at() to authenticated, service_role, postgres;
grant execute on function public.handle_new_user() to supabase_auth_admin, service_role, postgres;
grant execute on function public.sync_profile_email() to supabase_auth_admin, service_role, postgres;
grant execute on function public.protect_profile_row() to authenticated, service_role, postgres;

grant execute on function public.current_user_is_active() to authenticated, service_role;
grant execute on function public.is_org_active(uuid) to authenticated, service_role;
grant execute on function public.is_org_reader(uuid) to authenticated, service_role;
grant execute on function public.is_org_admin(uuid) to authenticated, service_role;
grant execute on function public.has_org_visibility(uuid) to authenticated, service_role;
grant execute on function public.is_brand_member(uuid) to authenticated, service_role;
grant execute on function public.has_brand_access(uuid) to authenticated, service_role;
grant execute on function public.can_admin_brand(uuid) to authenticated, service_role;
grant execute on function public.can_assign_brand_access(uuid) to authenticated, service_role;
grant execute on function public.can_read_profile(uuid) to authenticated, service_role;
grant execute on function public.can_admin_profile(uuid) to authenticated, service_role;

grant usage on type public.access_scope to authenticated, service_role;

grant select on table public.roles to authenticated, service_role;
grant select, update on table public.organizations to authenticated;
grant select, insert, update on table public.brands to authenticated;
grant select, update on table public.profiles to authenticated;
grant select, insert, update on table public.organization_memberships to authenticated;
grant select, insert, update on table public.brand_memberships to authenticated;

grant all on table public.organizations to service_role;
grant all on table public.roles to service_role;
grant all on table public.brands to service_role;
grant all on table public.profiles to service_role;
grant all on table public.organization_memberships to service_role;
grant all on table public.brand_memberships to service_role;

revoke all on table public.organizations from anon;
revoke all on table public.roles from anon;
revoke all on table public.brands from anon;
revoke all on table public.profiles from anon;
revoke all on table public.organization_memberships from anon;
revoke all on table public.brand_memberships from anon;
