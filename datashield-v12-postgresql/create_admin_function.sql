-- create_admin_function.sql

CREATE OR REPLACE FUNCTION datashield_cache_reload()
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_admin.so', 'datashield_cache_reload'
  LANGUAGE C; -- Menghapus STRICT karena fungsi ini tidak memiliki argumen

-- cara run
select datashield_cache_reload()  