-- create_all_functions.sql

-- Pustaka 1: voltage_udf_raw.so
CREATE OR REPLACE FUNCTION shield_raw(data text, format text, identity text, sharedsecret text)
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_raw.so', 'protectdata_raw'
  LANGUAGE C IMMUTABLE PARALLEL SAFE;

CREATE OR REPLACE FUNCTION unshield_raw(data text, format text, identity text, sharedsecret text)
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_raw.so', 'accessdata_raw'
  LANGUAGE C IMMUTABLE PARALLEL SAFE;

CREATE OR REPLACE FUNCTION mask_raw(data text, format text, identity text, sharedsecret text)
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_raw.so', 'maskdata_raw'
  LANGUAGE C IMMUTABLE PARALLEL SAFE;

-- Pustaka 2: voltage_udf_shield.so
CREATE OR REPLACE FUNCTION shield(data text, format text, config_id integer)
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_shield.so', 'shield'
  LANGUAGE C IMMUTABLE PARALLEL SAFE;

CREATE OR REPLACE FUNCTION unshield(data text, format text, config_id integer)
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_shield.so', 'unshield'
  LANGUAGE C IMMUTABLE PARALLEL SAFE;
  
CREATE OR REPLACE FUNCTION shieldmask(data text, format text, config_id integer)
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_shield.so', 'shieldmask'
  LANGUAGE C IMMUTABLE PARALLEL SAFE;

-- Pustaka 3: voltage_udf_maskdyn.so
CREATE OR REPLACE FUNCTION maskdyn_raw(data text, format text, identity text, sharedsecret text, mask_pattern text)
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_maskdyn.so', 'maskdyn_raw'
  LANGUAGE C IMMUTABLE PARALLEL SAFE;
  
CREATE OR REPLACE FUNCTION shieldmaskdyn(data text, format text, config_id integer, mask_pattern text)
  RETURNS text
  AS '/opt/db-postgresql/pgsql-15/lib/voltage_udf_maskdyn.so', 'shieldmaskdyn'
  LANGUAGE C IMMUTABLE PARALLEL SAFE;