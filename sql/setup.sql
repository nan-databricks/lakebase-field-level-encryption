-- ============================================================================
-- Lakebase Field-Level Encryption — paste-into-SQL-editor setup
-- ----------------------------------------------------------------------------
-- Idempotent. Safe to re-run. Creates a `vault.keys`-based CMK by default
-- so you can demo without an external bootstrap. For a real app, REMOVE the
-- vault.keys table and have your app set `SELECT set_config('app.cmk', ...)`
-- per session after fetching the key from Azure Key Vault / KMS.
-- ============================================================================

-- 1. Extension + schemas
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS my_vault;
CREATE SCHEMA IF NOT EXISTS my_app;

-- 2. The CMK vault — locked down to nobody by default.
--    In production: drop this table and use `current_setting('app.cmk')`
--    populated by the application from AKV / KMS at session start.
CREATE TABLE IF NOT EXISTS my_vault.keys (
    key_name   text PRIMARY KEY,
    key_value  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON my_vault.keys  FROM PUBLIC;
REVOKE USAGE ON SCHEMA my_vault FROM PUBLIC;

-- Seed a demo CMK. Replace with your own random string or rotate later.
INSERT INTO my_vault.keys(key_name, key_value)
VALUES ('default', 'replace-me-with-a-real-cmk-' || gen_random_uuid())
ON CONFLICT (key_name) DO NOTHING;

-- 3. Two SECURITY DEFINER decrypt functions.
--    The CMK never crosses a role boundary — only the function output does.
CREATE OR REPLACE FUNCTION my_vault.decrypt_full(
    p_ct bytea,
    p_key_name text DEFAULT 'default'
) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER STABLE
SET search_path = my_vault, public, pg_temp
AS $$
DECLARE v_key text;
BEGIN
    SELECT key_value INTO v_key FROM my_vault.keys WHERE key_name = p_key_name;
    IF v_key IS NULL THEN RETURN NULL; END IF;
    RETURN public.pgp_sym_decrypt(p_ct, v_key);
END;
$$;

CREATE OR REPLACE FUNCTION my_vault.decrypt_masked(
    p_ct bytea,
    p_strategy text,
    p_key_name text DEFAULT 'default'
) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER STABLE
SET search_path = my_vault, public, pg_temp
AS $$
DECLARE v_key text; v_plain text;
BEGIN
    SELECT key_value INTO v_key FROM my_vault.keys WHERE key_name = p_key_name;
    IF v_key IS NULL THEN RETURN NULL; END IF;
    v_plain := public.pgp_sym_decrypt(p_ct, v_key);
    RETURN CASE p_strategy
        WHEN 'email' THEN regexp_replace(v_plain, '(^.).*(@.*$)', '\1***\2')
        WHEN 'ssn'   THEN 'XXX-XX-' || right(v_plain, 4)
        WHEN 'card'  THEN '************' || right(v_plain, 4)
        WHEN 'phone' THEN '***-***-' || right(v_plain, 4)
        ELSE '***REDACTED***'
    END;
END;
$$;

-- 4. Roles
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pii_full_access')  THEN CREATE ROLE pii_full_access;  END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pii_masked')       THEN CREATE ROLE pii_masked;       END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='demo_pii_user')    THEN CREATE ROLE demo_pii_user;    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='demo_masked_user') THEN CREATE ROLE demo_masked_user; END IF;
END $$;

GRANT pii_full_access TO demo_pii_user;
GRANT pii_masked      TO demo_masked_user;
-- Let your workspace identity SET ROLE to either demo user:
GRANT demo_pii_user, demo_masked_user TO CURRENT_USER;

-- 5. The base table — PII as bytea ciphertext
CREATE TABLE IF NOT EXISTS my_app.customers (
    id              bigserial PRIMARY KEY,
    full_name       text         NOT NULL,
    email_enc       bytea        NOT NULL,
    ssn_enc         bytea        NOT NULL,
    card_number_enc bytea        NOT NULL,
    created_at      timestamptz  NOT NULL DEFAULT now()
);

-- 6. Insert helper — callers don't need the CMK directly.
CREATE OR REPLACE FUNCTION my_app.add_customer(
    p_name text, p_email text, p_ssn text, p_card text
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = my_app, my_vault, public, pg_temp
AS $$
DECLARE v_key text; v_id bigint;
BEGIN
    SELECT key_value INTO v_key FROM my_vault.keys WHERE key_name='default';
    INSERT INTO my_app.customers(full_name, email_enc, ssn_enc, card_number_enc)
    VALUES (p_name,
            public.pgp_sym_encrypt(p_email, v_key),
            public.pgp_sym_encrypt(p_ssn,   v_key),
            public.pgp_sym_encrypt(p_card,  v_key))
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

-- 7. Role-specific views — each calls EXACTLY ONE decrypt function so
--    Postgres' planner-level permission check is also enforced.
CREATE OR REPLACE VIEW my_app.customers_full AS
SELECT id, full_name,
       my_vault.decrypt_full(email_enc)        AS email,
       my_vault.decrypt_full(ssn_enc)          AS ssn,
       my_vault.decrypt_full(card_number_enc)  AS card_number,
       created_at
FROM my_app.customers;

CREATE OR REPLACE VIEW my_app.customers_masked AS
SELECT id, full_name,
       my_vault.decrypt_masked(email_enc,       'email') AS email,
       my_vault.decrypt_masked(ssn_enc,         'ssn')   AS ssn,
       my_vault.decrypt_masked(card_number_enc, 'card')  AS card_number,
       created_at
FROM my_app.customers;

-- 8. Lock everything down, then grant the minimum each role needs.
REVOKE ALL ON my_vault.keys FROM pii_full_access, pii_masked, PUBLIC;
REVOKE EXECUTE ON FUNCTION my_vault.decrypt_full(bytea,text)        FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION my_vault.decrypt_masked(bytea,text,text) FROM PUBLIC;

GRANT USAGE   ON SCHEMA my_vault   TO pii_full_access, pii_masked;
GRANT USAGE   ON SCHEMA my_app     TO pii_full_access, pii_masked;
GRANT EXECUTE ON FUNCTION my_vault.decrypt_full(bytea,text)        TO pii_full_access;
GRANT EXECUTE ON FUNCTION my_vault.decrypt_masked(bytea,text,text) TO pii_masked;
GRANT EXECUTE ON FUNCTION my_app.add_customer(text,text,text,text) TO pii_full_access;
GRANT SELECT  ON my_app.customers_full   TO pii_full_access;
GRANT SELECT  ON my_app.customers_masked TO pii_masked;

-- ============================================================================
-- Done. Insert sample data and try it out:
-- ============================================================================

-- SELECT my_app.add_customer('Alice Anderson', 'alice@acme.com',  '123-45-6789', '4111111111111111');
-- SELECT my_app.add_customer('Bob Brown',      'bob@globex.com',  '987-65-4321', '5500000000000004');
--
-- SET ROLE demo_pii_user;
-- SELECT * FROM my_app.customers_full ORDER BY id;
-- RESET ROLE;
--
-- SET ROLE demo_masked_user;
-- SELECT * FROM my_app.customers_masked ORDER BY id;
-- RESET ROLE;

-- ============================================================================
-- CMK rotation — re-encrypt every row in one transaction
-- ============================================================================
-- BEGIN;
-- WITH old AS (SELECT key_value FROM my_vault.keys WHERE key_name='default'),
--      new AS (SELECT 'rotated-' || gen_random_uuid()::text AS k)
-- UPDATE my_app.customers c
-- SET email_enc       = pgp_sym_encrypt(pgp_sym_decrypt(c.email_enc,       (SELECT key_value FROM old)), (SELECT k FROM new)),
--     ssn_enc         = pgp_sym_encrypt(pgp_sym_decrypt(c.ssn_enc,         (SELECT key_value FROM old)), (SELECT k FROM new)),
--     card_number_enc = pgp_sym_encrypt(pgp_sym_decrypt(c.card_number_enc, (SELECT key_value FROM old)), (SELECT k FROM new));
-- UPDATE my_vault.keys SET key_value = (SELECT 'rotated-' || gen_random_uuid()::text) WHERE key_name='default';
-- COMMIT;
