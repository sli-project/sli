do $$
begin
  raise exception
    'migration 132 is one-way authorization hardening; rollback would restore forgeable manifest/output delete authorization';
end
$$;
