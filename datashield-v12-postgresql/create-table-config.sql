-- create-table-config.sql

-- Membuat skema untuk kerapian dan keamanan
CREATE SCHEMA IF NOT EXISTS datashield;

-- Membuat tabel untuk menyimpan kredensial
-- Menggunakan 'IF NOT EXISTS' untuk mencegah error jika tabel sudah ada
CREATE TABLE IF NOT EXISTS datashield.credentials (
    config_id    INTEGER PRIMARY KEY,
    identity     TEXT NOT NULL,
    sharedsecret TEXT NOT NULL,
    description  TEXT
);

-- Masukkan data contoh jika belum ada
INSERT INTO datashield.credentials (config_id, identity, sharedsecret, description) VALUES
(1, 'admin@voltage.co.id', 'voltage123', 'Admin Credentials')
ON CONFLICT (config_id) DO NOTHING;

INSERT INTO datashield.credentials (config_id, identity, sharedsecret, description) VALUES
(2, 'branch.texas.1231@transit.file', 'ranger123', 'Branch Texas Credentials')
ON CONFLICT (config_id) DO NOTHING;

-- Berikan hak akses kepada user yang akan menjalankan UDF
-- Ganti 'postgres' jika Anda menggunakan user lain
GRANT USAGE ON SCHEMA datashield TO postgres;
GRANT SELECT ON datashield.credentials TO postgres;