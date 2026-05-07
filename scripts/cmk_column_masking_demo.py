"""
Column Masking on Lakebase using a Customer-Managed Key (CMK) pattern.

What this demo shows:
  1. A `vault.keys` table holds the CMK (in real life this is fetched from
     Databricks Secrets / AWS KMS at session start; we simulate it in-DB).
  2. `vault.get_cmk()` is a SECURITY DEFINER function that only returns the
     key to members of the `pii_full_access` role.
  3. The `customers` table stores PII (`email`, `ssn`, `card_number`) as
     `bytea` ciphertext via `pgcrypto.pgp_sym_encrypt()`.
  4. A view `customers_v` decrypts on read:
       - members of `pii_full_access`  -> plaintext
       - members of `pii_masked`        -> masked / redacted values
       - everyone else                  -> NULL
  5. We create two demo users (`demo_pii_user`, `demo_masked_user`),
     grant them the right roles, and run the same SELECT as each of them
     to prove what they can and cannot see.

Run with:
    DATABRICKS_CONFIG_PROFILE=nan-demo python3 cmk_column_masking_demo.py
"""

from __future__ import annotations

import os
import sys
import textwrap

import psycopg
from databricks.sdk import WorkspaceClient

PROFILE = os.environ.get("DATABRICKS_CONFIG_PROFILE", "nan-demo")
PROJECT = "projects/lakebase-bank-poc"
ENDPOINT = f"{PROJECT}/branches/production/endpoints/primary"
DBNAME = "databricks_postgres"

DEMO_SCHEMA = "cmk_demo"
VAULT_SCHEMA = "vault"

DEMO_CMK = "demo-master-key-rotated-2026-05"


def banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def run(cur, sql: str, *, args=None, quiet=False) -> None:
    if not quiet:
        first_line = sql.strip().splitlines()[0][:90]
        print(f"  SQL> {first_line}{' ...' if len(sql.strip().splitlines()) > 1 else ''}")
    cur.execute(sql, args)


def print_rows(cur, header: str) -> None:
    cols = [d.name for d in cur.description] if cur.description else []
    rows = cur.fetchall()
    print(f"\n  {header}")
    print("  " + "-" * (len(header) + 2))
    if not rows:
        print("    (no rows)")
        return
    widths = [
        max(len(c), *(len(str(r[i])) for r in rows)) for i, c in enumerate(cols)
    ]
    print("    " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cols)))
    print("    " + "-+-".join("-" * w for w in widths))
    for r in rows:
        print("    " + " | ".join(str(r[i]).ljust(widths[i]) for i in range(len(cols))))


def connect(host: str, user: str, token: str) -> psycopg.Connection:
    """Connect to Lakebase. macOS DNS workaround via hostaddr."""
    import socket

    hostaddr = socket.gethostbyname(host)
    return psycopg.connect(
        host=host,
        hostaddr=hostaddr,
        dbname=DBNAME,
        user=user,
        password=token,
        sslmode="require",
        autocommit=True,
    )


def main() -> int:
    banner("Step 0: bootstrap Databricks SDK + get an OAuth token")
    w = WorkspaceClient(profile=PROFILE)
    me = w.current_user.me().user_name
    print(f"  Profile : {PROFILE}")
    print(f"  User    : {me}")

    ep = w.postgres.get_endpoint(name=ENDPOINT)
    host = ep.status.hosts.host
    print(f"  Host    : {host}")

    cred = w.postgres.generate_database_credential(endpoint=ENDPOINT)
    token = cred.token
    print(f"  Token   : (1h OAuth token, len={len(token)})")

    banner("Step 1: connect as the workspace user (admin) and set up the vault")
    with connect(host, me, token) as conn, conn.cursor() as cur:
        run(cur, "CREATE EXTENSION IF NOT EXISTS pgcrypto;")
        run(cur, f'CREATE SCHEMA IF NOT EXISTS {VAULT_SCHEMA};')
        run(cur, f'CREATE SCHEMA IF NOT EXISTS {DEMO_SCHEMA};')

        run(cur, f"""
            CREATE TABLE IF NOT EXISTS {VAULT_SCHEMA}.keys (
                key_name    text PRIMARY KEY,
                key_value   text NOT NULL,
                created_at  timestamptz NOT NULL DEFAULT now()
            );
        """)

        # Lock down vault.keys -- only key_admin can SELECT
        run(cur, f"REVOKE ALL ON {VAULT_SCHEMA}.keys FROM PUBLIC;")
        run(cur, f"REVOKE USAGE ON SCHEMA {VAULT_SCHEMA} FROM PUBLIC;")

        run(cur, f"""
            INSERT INTO {VAULT_SCHEMA}.keys(key_name, key_value)
            VALUES ('default', %s)
            ON CONFLICT (key_name) DO UPDATE SET key_value = EXCLUDED.key_value;
        """, args=(DEMO_CMK,))

        # Two SECURITY DEFINER functions, each ACL-locked via GRANT EXECUTE:
        #
        #   vault.decrypt_full(ct, key_name)
        #     - returns plaintext
        #     - GRANT EXECUTE only to pii_full_access
        #
        #   vault.decrypt_masked(ct, strategy, key_name)
        #     - decrypts internally, then applies a mask,
        #       and returns ONLY the masked string
        #     - GRANT EXECUTE only to pii_masked
        #
        # The CMK never crosses a role boundary -- only the post-mask result
        # leaves the function for masked users. SECURITY DEFINER lets these
        # functions read vault.keys without granting the caller any access.
        run(cur, f"""
            CREATE OR REPLACE FUNCTION {VAULT_SCHEMA}.decrypt_full(
                p_ct bytea,
                p_key_name text DEFAULT 'default'
            ) RETURNS text
            LANGUAGE plpgsql
            SECURITY DEFINER
            STABLE
            SET search_path = {VAULT_SCHEMA}, public, pg_temp
            AS $$
            DECLARE
                v_key text;
            BEGIN
                SELECT key_value INTO v_key FROM {VAULT_SCHEMA}.keys WHERE key_name = p_key_name;
                IF v_key IS NULL THEN RETURN NULL; END IF;
                RETURN public.pgp_sym_decrypt(p_ct, v_key);
            END;
            $$;
        """)

        run(cur, f"""
            CREATE OR REPLACE FUNCTION {VAULT_SCHEMA}.decrypt_masked(
                p_ct bytea,
                p_strategy text,
                p_key_name text DEFAULT 'default'
            ) RETURNS text
            LANGUAGE plpgsql
            SECURITY DEFINER
            STABLE
            SET search_path = {VAULT_SCHEMA}, public, pg_temp
            AS $$
            DECLARE
                v_key   text;
                v_plain text;
            BEGIN
                SELECT key_value INTO v_key FROM {VAULT_SCHEMA}.keys WHERE key_name = p_key_name;
                IF v_key IS NULL THEN RETURN NULL; END IF;
                v_plain := public.pgp_sym_decrypt(p_ct, v_key);

                RETURN CASE p_strategy
                    WHEN 'email' THEN regexp_replace(v_plain, '(^.).*(@.*$)', '\\1***\\2')
                    WHEN 'ssn'   THEN 'XXX-XX-' || right(v_plain, 4)
                    WHEN 'card'  THEN '************' || right(v_plain, 4)
                    ELSE '***REDACTED***'
                END;
            END;
            $$;
        """)

        banner("Step 2: create the demo customers table (PII as bytea ciphertext)")
        run(cur, f"""
            DROP TABLE IF EXISTS {DEMO_SCHEMA}.customers CASCADE;
        """)
        run(cur, f"""
            CREATE TABLE {DEMO_SCHEMA}.customers (
                id              bigserial PRIMARY KEY,
                full_name       text          NOT NULL,
                email_enc       bytea         NOT NULL,   -- encrypted
                ssn_enc         bytea         NOT NULL,   -- encrypted
                card_number_enc bytea         NOT NULL,   -- encrypted
                created_at      timestamptz   NOT NULL DEFAULT now()
            );
        """)

        banner("Step 3: create role-specific views (full + masked) + insert helper")
        # Two views, one per role. Each calls EXACTLY ONE decrypt function, so
        # planner-level permission checks are also enforced (no leak via
        # planner inspection of unused CASE branches). Customers query
        # whichever view their role can SELECT from -- you can also expose
        # both as `customers_v` per-role using a SECURITY INVOKER wrapper.

        # FULL view -- only pii_full_access can SELECT
        run(cur, f"""
            CREATE OR REPLACE VIEW {DEMO_SCHEMA}.customers_full AS
            SELECT
                c.id,
                c.full_name,
                {VAULT_SCHEMA}.decrypt_full(c.email_enc)        AS email,
                {VAULT_SCHEMA}.decrypt_full(c.ssn_enc)          AS ssn,
                {VAULT_SCHEMA}.decrypt_full(c.card_number_enc)  AS card_number,
                c.created_at
            FROM {DEMO_SCHEMA}.customers c;
        """)

        # MASKED view -- only pii_masked can SELECT
        run(cur, f"""
            CREATE OR REPLACE VIEW {DEMO_SCHEMA}.customers_masked AS
            SELECT
                c.id,
                c.full_name,
                {VAULT_SCHEMA}.decrypt_masked(c.email_enc,       'email') AS email,
                {VAULT_SCHEMA}.decrypt_masked(c.ssn_enc,         'ssn')   AS ssn,
                {VAULT_SCHEMA}.decrypt_masked(c.card_number_enc, 'card')  AS card_number,
                c.created_at
            FROM {DEMO_SCHEMA}.customers c;
        """)

        # An INSERT helper -- callers don't need the CMK directly.
        run(cur, f"""
            CREATE OR REPLACE FUNCTION {DEMO_SCHEMA}.add_customer(
                p_name text, p_email text, p_ssn text, p_card text
            ) RETURNS bigint
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = {DEMO_SCHEMA}, {VAULT_SCHEMA}, pg_temp
            AS $$
            DECLARE
                v_key text;
                v_id  bigint;
            BEGIN
                SELECT key_value INTO v_key FROM {VAULT_SCHEMA}.keys WHERE key_name = 'default';
                INSERT INTO {DEMO_SCHEMA}.customers(full_name, email_enc, ssn_enc, card_number_enc)
                VALUES (
                    p_name,
                    public.pgp_sym_encrypt(p_email, v_key),
                    public.pgp_sym_encrypt(p_ssn,   v_key),
                    public.pgp_sym_encrypt(p_card,  v_key)
                )
                RETURNING id INTO v_id;
                RETURN v_id;
            END;
            $$;
        """)

        banner("Step 4: create roles + demo users")
        for role in ("pii_full_access", "pii_masked", "demo_pii_user", "demo_masked_user"):
            run(cur, f"""
                DO $$ BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                        CREATE ROLE {role};
                    END IF;
                END $$;
            """, quiet=True)

        # Allow the workspace identity to act as either demo user (SET ROLE).
        run(cur, f'GRANT pii_full_access TO demo_pii_user;')
        run(cur, f'GRANT pii_masked      TO demo_masked_user;')
        run(cur, f'GRANT demo_pii_user, demo_masked_user TO "{me}";')

        # Schema + view privileges -- split so each role only sees its own view
        run(cur, f'GRANT USAGE ON SCHEMA {DEMO_SCHEMA} TO pii_full_access, pii_masked;')
        run(cur, f'GRANT SELECT ON {DEMO_SCHEMA}.customers_full   TO pii_full_access;')
        run(cur, f'GRANT SELECT ON {DEMO_SCHEMA}.customers_masked TO pii_masked;')
        run(cur, f'GRANT EXECUTE ON FUNCTION {DEMO_SCHEMA}.add_customer(text,text,text,text) TO pii_full_access;')

        # vault grants:
        #   - both roles need USAGE on schema
        #   - pii_full_access:  EXECUTE on decrypt_full  (returns plaintext)
        #   - pii_masked:       EXECUTE on decrypt_masked (returns masked str)
        #   - NEITHER role gets SELECT on vault.keys -> CMK never leaves
        #     the SECURITY DEFINER functions
        run(cur, f'REVOKE ALL ON {VAULT_SCHEMA}.keys FROM pii_full_access, pii_masked, PUBLIC;')
        run(cur, f'REVOKE EXECUTE ON FUNCTION {VAULT_SCHEMA}.decrypt_full(bytea,text)         FROM PUBLIC;')
        run(cur, f'REVOKE EXECUTE ON FUNCTION {VAULT_SCHEMA}.decrypt_masked(bytea,text,text)  FROM PUBLIC;')
        run(cur, f'GRANT USAGE ON SCHEMA {VAULT_SCHEMA} TO pii_full_access, pii_masked;')
        run(cur, f'GRANT EXECUTE ON FUNCTION {VAULT_SCHEMA}.decrypt_full(bytea,text)         TO pii_full_access;')
        run(cur, f'GRANT EXECUTE ON FUNCTION {VAULT_SCHEMA}.decrypt_masked(bytea,text,text)  TO pii_masked;')

        banner("Step 5: insert sample customers (encrypted at rest)")
        sample = [
            ("Alice Anderson", "alice.anderson@acme.com",   "123-45-6789", "4111111111111111"),
            ("Bob Brown",      "bob.brown@globex.com",      "987-65-4321", "5500000000000004"),
            ("Carol Chen",     "carol.chen@initech.com",    "555-12-3456", "340000000000009"),
            ("Dan Davis",      "dan.davis@umbrella.corp",   "111-22-3333", "30000000000004"),
        ]
        for name, email, ssn, card in sample:
            run(cur, f"SELECT {DEMO_SCHEMA}.add_customer(%s,%s,%s,%s)",
                args=(name, email, ssn, card), quiet=True)
        print(f"  Inserted {len(sample)} encrypted customers.")

        banner("Step 6: peek at the raw ciphertext (admin view of bytea)")
        run(cur, f"""
            SELECT id, full_name,
                   substring(encode(email_enc,'hex') for 32) || '...' AS email_enc_hex,
                   substring(encode(ssn_enc,'hex')   for 32) || '...' AS ssn_enc_hex
            FROM {DEMO_SCHEMA}.customers
            ORDER BY id;
        """)
        print_rows(cur, "Raw bytea (what an attacker stealing the table would see):")

        banner("Step 7a: query as demo_pii_user (privileged) -> customers_full")
        run(cur, "SET ROLE demo_pii_user;")
        run(cur, f"SELECT id, full_name, email, ssn, card_number FROM {DEMO_SCHEMA}.customers_full ORDER BY id;")
        print_rows(cur, "demo_pii_user sees PLAINTEXT:")
        run(cur, "RESET ROLE;")

        banner("Step 7b: query as demo_masked_user -> customers_masked")
        run(cur, "SET ROLE demo_masked_user;")
        run(cur, f"SELECT id, full_name, email, ssn, card_number FROM {DEMO_SCHEMA}.customers_masked ORDER BY id;")
        print_rows(cur, "demo_masked_user sees MASKED values:")
        run(cur, "RESET ROLE;")

        banner("Step 7c: confirm demo_masked_user CANNOT touch the privileged view / key / fn")
        # 7c-i: tries to SELECT customers_full
        run(cur, "SET ROLE demo_masked_user;")
        try:
            cur.execute(f"SELECT email FROM {DEMO_SCHEMA}.customers_full LIMIT 1;")
            print(f"  ! UNEXPECTED: read customers_full -> {cur.fetchall()}")
        except Exception as e:
            print(f"  Blocked SELECT on customers_full: {type(e).__name__}: {str(e).splitlines()[0]}")
        cur.execute("RESET ROLE;")

        # 7c-ii: tries direct SELECT on vault.keys
        run(cur, "SET ROLE demo_masked_user;")
        try:
            cur.execute(f"SELECT key_value FROM {VAULT_SCHEMA}.keys WHERE key_name='default';")
            print(f"  ! UNEXPECTED: read vault.keys -> {cur.fetchall()}")
        except Exception as e:
            print(f"  Blocked SELECT on vault.keys: {type(e).__name__}: {str(e).splitlines()[0]}")
        cur.execute("RESET ROLE;")

        # 7c-iii: tries to call decrypt_full directly
        run(cur, "SET ROLE demo_masked_user;")
        try:
            cur.execute(f"SELECT {VAULT_SCHEMA}.decrypt_full((SELECT email_enc FROM {DEMO_SCHEMA}.customers LIMIT 1));")
            print(f"  ! UNEXPECTED: decrypt_full returned -> {cur.fetchall()}")
        except Exception as e:
            print(f"  Blocked EXECUTE on vault.decrypt_full: {type(e).__name__}: {str(e).splitlines()[0]}")
        cur.execute("RESET ROLE;")

        # 7c-iv: tries to call pgp_sym_decrypt directly with a hard-coded guess
        run(cur, "SET ROLE demo_masked_user;")
        try:
            cur.execute(f"""
                SELECT public.pgp_sym_decrypt(email_enc, 'guess')
                FROM {DEMO_SCHEMA}.customers LIMIT 1;
            """)
            print(f"  ! UNEXPECTED: direct pgp_sym_decrypt returned -> {cur.fetchall()}")
        except Exception as e:
            print(f"  Blocked direct pgcrypto + raw table read: {type(e).__name__}: {str(e).splitlines()[0]}")
        cur.execute("RESET ROLE;")

        banner("Step 7d: confirm an unprivileged role sees neither view")
        run(cur, """
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='nobody_role') THEN
                    CREATE ROLE nobody_role;
                END IF;
            END $$;
        """, quiet=True)
        run(cur, f'GRANT USAGE ON SCHEMA {DEMO_SCHEMA} TO nobody_role;')
        run(cur, f'GRANT nobody_role TO "{me}";')
        run(cur, "SET ROLE nobody_role;")
        for view in ("customers_full", "customers_masked"):
            try:
                cur.execute(f"SELECT 1 FROM {DEMO_SCHEMA}.{view} LIMIT 1;")
                print(f"  ! UNEXPECTED: read {view}")
            except Exception as e:
                print(f"  Blocked {view}: {type(e).__name__}: {str(e).splitlines()[0]}")
            cur.execute("RESET ROLE;")
            cur.execute("SET ROLE nobody_role;")
        cur.execute("RESET ROLE;")

        banner("Step 8: demonstrate CMK rotation")
        new_key = "demo-master-key-ROTATED-2026-05-08"
        # Rotate: re-encrypt every row with the new key in a single statement
        run(cur, f"""
            WITH old AS (SELECT key_value FROM {VAULT_SCHEMA}.keys WHERE key_name='default')
            UPDATE {DEMO_SCHEMA}.customers c
            SET email_enc       = public.pgp_sym_encrypt(public.pgp_sym_decrypt(c.email_enc,       (SELECT key_value FROM old)), %s),
                ssn_enc         = public.pgp_sym_encrypt(public.pgp_sym_decrypt(c.ssn_enc,         (SELECT key_value FROM old)), %s),
                card_number_enc = public.pgp_sym_encrypt(public.pgp_sym_decrypt(c.card_number_enc, (SELECT key_value FROM old)), %s);
        """, args=(new_key, new_key, new_key))
        run(cur, f"UPDATE {VAULT_SCHEMA}.keys SET key_value=%s WHERE key_name='default';", args=(new_key,))
        print("  CMK rotated; all rows re-encrypted under the new key.")

        run(cur, "SET ROLE demo_pii_user;")
        run(cur, f"SELECT id, full_name, email FROM {DEMO_SCHEMA}.customers_full ORDER BY id;")
        print_rows(cur, "Post-rotation read by demo_pii_user (still works):")
        run(cur, "RESET ROLE;")

        banner("Done.")
        print(textwrap.dedent(f"""
          Project        : {PROJECT}
          Endpoint host  : {host}
          Database       : {DBNAME}
          Schemas        : {VAULT_SCHEMA}, {DEMO_SCHEMA}
          Table          : {DEMO_SCHEMA}.customers          (PII as bytea ciphertext)
          Views          : {DEMO_SCHEMA}.customers_full     (plaintext, granted to pii_full_access)
                           {DEMO_SCHEMA}.customers_masked   (masked,    granted to pii_masked)
          Helper fn      : {DEMO_SCHEMA}.add_customer(name,email,ssn,card)
          Vault fns      : {VAULT_SCHEMA}.decrypt_full(ct)            -> pii_full_access only
                           {VAULT_SCHEMA}.decrypt_masked(ct,strategy) -> pii_masked only
          Roles          : pii_full_access  -> sees plaintext
                           pii_masked       -> sees masked values
                           (other)          -> blocked at the view layer
        """).strip())

    return 0


if __name__ == "__main__":
    sys.exit(main())
