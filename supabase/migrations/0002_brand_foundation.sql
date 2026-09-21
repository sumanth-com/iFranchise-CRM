-- iFranchise CRM — initial brand foundation
--
-- Inserts the three active operating brands under the iFranchise organization.
-- Does not create brand memberships, Brand Owner users, or CRM business records.
-- Relies on existing has_brand_access() / is_org_reader() RLS from 0001.

do $$
declare
  org_id uuid;
  inserted_count integer;
begin
  perform set_config('search_path', '', true);

  select o.id
  into org_id
  from public.organizations as o
  where o.slug = 'ifranchise'
    and o.archived_at is null;

  if org_id is null then
    raise exception 'Active organization with slug ifranchise was not found. Run DEV bootstrap first.';
  end if;

  insert into public.brands (organization_id, name, slug)
  values
    (org_id, 'Odette', 'odette'),
    (org_id, 'Original Burger Co', 'original-burger-co'),
    (org_id, 'Kasturi', 'kasturi');

  get diagnostics inserted_count = row_count;

  if inserted_count <> 3 then
    raise exception 'Expected to insert 3 brands, inserted %.', inserted_count;
  end if;
end;
$$;
