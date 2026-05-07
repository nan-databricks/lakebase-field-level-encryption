# Beyond Encryption-at-Rest: Column-Level Encryption and Dynamic Masking on Databricks Lakebase

> A practical, copy-paste-able guide to protecting PII in operational Postgres on Databricks — using `pgcrypto`, a customer-managed key from Azure Key Vault, and role-based masking views.

![Architecture: AKV → Databricks Secret Scope → Lakebase session → masking views](images/architecture.png)

---

## The objective

You've spun up [Lakebase](https://docs.databricks.com/aws/en/oltp/), Databricks' managed Postgres, to power an operational application — maybe a credit-decisioning service, a customer 360 lookup, or an account-status microservice. The table holds emails, SSNs, card numbers. Two operational apps now read from it:

1. **A fraud console** used by internal analysts who legitimately need the full PII to investigate cases.
2. **A customer 360 / support app** where the agent only needs the last four digits of an SSN to verify a caller.

Both apps run as Databricks Apps with their own service principals. Both query the same `customers` table. Your platform team already enabled storage-level encryption with a customer-managed key — the disk is encrypted. So you're done, right?

No. Encryption-at-rest only protects you against one specific attacker (the one who steals the disk). Both apps above log in as legitimate users and run `SELECT *`. To them, the disk-level encryption is invisible — and a leaked credential or compromised app instance gives the attacker exactly the same view.

(Side note: this is an OLTP problem. If you also need analytics on this data, that lives in the Lakehouse — sync the *masked* view to Delta and apply Unity Catalog column masks there. Lakebase is for operational apps; Power BI / Tableau should not point at it.)

This post is about adding the second layer: **column-level encryption with dynamic masking**, so the same row in the same table looks completely different depending on who's reading.

---

## Why this is *not* the same as encryption-at-rest

![Encryption at rest vs column-level encryption — same table, different threats](images/at_rest_vs_column.png)

Encryption-at-rest is a **storage-tier** control. The database engine still sees plaintext. Anyone who authenticates and runs `SELECT` gets cleartext rows back. It's a perfectly good control for the threat it targets — disk theft, snapshot exfiltration, backup leakage — but it does nothing for:

- A compromised app credential or service principal
- An overprivileged engineer querying via the SQL editor
- An internal microservice that legitimately connects with a service account but is breached
- A `pg_dump` accidentally posted to an internal wiki

**Column-level encryption** is an **application-tier** control. The PII columns in your table are *bytea ciphertext on disk and in memory*. Plaintext only exists for the moment a privileged role calls a decrypt function — and even then, only for that role. You can layer a *masked* decrypt path so other roles see redacted strings. The result:

- Stolen backup → still ciphertext (same as at-rest)
- Compromised role → only that role's view (mask or NULL)
- DBA running ad-hoc queries → ciphertext only
- Audit logs → "user X called `decrypt_full` 47 times today" — per-column, per-role, per-strategy

You want **both layers**. They don't replace each other; they protect different attackers.

---

## Architecture: where each piece lives

The pattern has four moving parts:

1. **The CMK** lives in **Azure Key Vault** (or AWS KMS / GCP KMS).
2. **A Databricks Secret Scope**, backed by AKV, surfaces the CMK to authorized Databricks Apps with a single API call. Every read is audited in Azure Monitor *and* Databricks audit logs.
3. **Lakebase Postgres** holds the table with PII as `bytea` ciphertext, plus two `SECURITY DEFINER` functions that decrypt — one returns plaintext, one returns *already-masked* strings. ACLs decide who can call which.
4. **Each Databricks App** authenticates as a different Postgres role: the Fraud Console as `pii_full_access`, the Customer 360 App as `pii_masked`. They both read the CMK once at session start, inject it into Postgres via a session-local GUC variable, then query their assigned view. The CMK never persists in Postgres.

The key never crosses a role boundary inside the database. The plaintext never leaves the decrypt function for masked users. Both `pii_full_access` and `pii_masked` see *the same row* through different windows.

---

## How to do it on Databricks

### Step 1 — Store the CMK in Azure Key Vault

```bash
az keyvault secret set \
    --vault-name my-customer-kv \
    --name lakebase-cmk \
    --value "$(openssl rand -base64 32)"
```

### Step 2 — Create an AKV-backed Databricks Secret Scope

In the Azure Databricks UI: **Settings → Secret scopes → + Add scope → Azure Key Vault backed**. Or via CLI:

```bash
databricks secrets create-scope lakebase-cmk \
    --scope-backend-type AZURE_KEYVAULT \
    --resource-id "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/my-customer-kv" \
    --dns-name "https://my-customer-kv.vault.azure.net/"
```

Now any Databricks App or job can fetch the key with `dbutils.secrets.get(...)` — and Databricks records it in the audit log.

### Step 3 — Build the encryption + masking layer in Lakebase

Open the Lakebase SQL Editor on your project and paste this. It's idempotent — safe to re-run.

```sql
-- 1. Enable pgcrypto and create schemas
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS my_vault;
CREATE SCHEMA IF NOT EXISTS my_app;

-- 2. SECURITY DEFINER decrypt functions. They read the CMK from the
--    session GUC `app.cmk` set by the application after fetching from AKV.
CREATE OR REPLACE FUNCTION my_vault.decrypt_full(p_ct bytea)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = my_vault, public, pg_temp
AS $$
BEGIN
    RETURN public.pgp_sym_decrypt(p_ct, current_setting('app.cmk'));
END; $$;

CREATE OR REPLACE FUNCTION my_vault.decrypt_masked(p_ct bytea, p_strategy text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = my_vault, public, pg_temp
AS $$
DECLARE v_plain text;
BEGIN
    v_plain := public.pgp_sym_decrypt(p_ct, current_setting('app.cmk'));
    RETURN CASE p_strategy
        WHEN 'email' THEN regexp_replace(v_plain, '(^.).*(@.*$)', '\1***\2')
        WHEN 'ssn'   THEN 'XXX-XX-' || right(v_plain, 4)
        WHEN 'card'  THEN '************' || right(v_plain, 4)
        ELSE '***REDACTED***'
    END;
END; $$;

-- 3. Roles + ACLs. Lock down EXECUTE so each role only reaches its
--    own decrypt path. The CMK never crosses a role boundary.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pii_full_access') THEN CREATE ROLE pii_full_access; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='pii_masked')      THEN CREATE ROLE pii_masked;      END IF;
END $$;
REVOKE EXECUTE ON FUNCTION my_vault.decrypt_full(bytea)         FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION my_vault.decrypt_masked(bytea, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION my_vault.decrypt_full(bytea)         TO pii_full_access;
GRANT  EXECUTE ON FUNCTION my_vault.decrypt_masked(bytea, text) TO pii_masked;

-- 4. The base table — PII as bytea ciphertext
CREATE TABLE IF NOT EXISTS my_app.customers (
    id              bigserial PRIMARY KEY,
    full_name       text         NOT NULL,
    email_enc       bytea        NOT NULL,
    ssn_enc         bytea        NOT NULL,
    card_number_enc bytea        NOT NULL,
    created_at      timestamptz  NOT NULL DEFAULT now()
);

-- 5. Two role-specific views — each calls exactly one decrypt path
CREATE OR REPLACE VIEW my_app.customers_full AS
SELECT id, full_name,
       my_vault.decrypt_full(email_enc)        AS email,
       my_vault.decrypt_full(ssn_enc)          AS ssn,
       my_vault.decrypt_full(card_number_enc)  AS card_number
FROM my_app.customers;

CREATE OR REPLACE VIEW my_app.customers_masked AS
SELECT id, full_name,
       my_vault.decrypt_masked(email_enc,       'email') AS email,
       my_vault.decrypt_masked(ssn_enc,         'ssn')   AS ssn,
       my_vault.decrypt_masked(card_number_enc, 'card')  AS card_number
FROM my_app.customers;

GRANT SELECT ON my_app.customers_full   TO pii_full_access;
GRANT SELECT ON my_app.customers_masked TO pii_masked;
```

> **Why two views instead of one with a `CASE`?** Postgres' planner pre-checks `EXECUTE` on *both* branches of a `CASE`, so a single view leaks the masked function's permission requirements to the privileged role. Two views, one per role, sidesteps the issue and matches the recommended production pattern for tiered sensitivity.

### Step 4 — Wire up the application

The app fetches the CMK from AKV via the Databricks secret scope, opens a Lakebase connection, sets the session GUC, then queries normally:

```python
import psycopg
from databricks.sdk import WorkspaceClient

w = WorkspaceClient(profile="nan-demo")

# 1. Fetch the CMK from Azure Key Vault via the AKV-backed scope
cmk = w.dbutils.secrets.get(scope="lakebase-cmk", key="lakebase-cmk")

# 2. Get a Lakebase OAuth token (1-hour expiry)
ep    = w.postgres.get_endpoint(name="projects/lakebase-bank-poc/branches/production/endpoints/primary")
token = w.postgres.generate_database_credential(endpoint=ep.name).token
host  = ep.status.hosts.host

# 3. Connect, inject the CMK into the session, query
with psycopg.connect(
    host=host, dbname="databricks_postgres",
    user=w.current_user.me().user_name, password=token, sslmode="require",
) as conn, conn.cursor() as cur:
    cur.execute("SELECT set_config('app.cmk', %s, false);", (cmk,))   # session-local
    cur.execute("SET ROLE demo_pii_user;")                            # or demo_masked_user
    cur.execute("SELECT id, email, ssn, card_number FROM my_app.customers_full;")
    for row in cur.fetchall():
        print(row)
```

The CMK lives in:

- **Azure Key Vault** — durable, audited, customer-controlled.
- **The Databricks Secret Scope** — proxied access, also audited.
- **The app's connection's session memory** — for the lifetime of the connection only.
- **Never on disk in Postgres.** Never in pg_stat_statements (use `set_config` not `SET app.cmk = '...'`).

If you have ad-hoc SQL Editor users who need access without running a Python bootstrap, swap step 4 for a tiny scheduled Databricks Job that fetches the CMK from AKV nightly and writes it into a `vault.keys` table locked down with `REVOKE ALL FROM PUBLIC`. The decrypt functions then read from that table instead of the GUC. Slightly more attack surface, much friendlier for break-glass / debugging access.

---

## See it in action

Same `customers` table, same query shape, two roles:

![Side-by-side: pii_full_access sees plaintext, pii_masked sees redacted, raw bytea is unintelligible](images/comparison.png)

The top-left panel is the fraud analyst's view — full PII. Top-right is the support agent's view — `XXX-XX-6789`, `a***@acme.com`, `************1111`. Bottom is what's actually in the table on disk: `bytea` ciphertext starting with `\xc30d04...` (the standard pgp message header). An attacker who steals a backup gets the bottom panel — useless without the CMK.

### Try to break it

What's interesting is everything the masked role *cannot* do, even though they know the schema:

![All four bypass attempts return 'permission denied'](images/bypass.png)

- ✗ `SELECT` from the privileged view → denied (no GRANT)
- ✗ `SELECT` from `vault.keys` (the legacy fallback path) → denied
- ✗ Call `decrypt_full` directly → denied (no EXECUTE)
- ✗ Call `pgcrypto` against the raw table with a guessed key → denied (no SELECT on base table)
- ✓ Call the masked view → `a***@acme.com`

This is the defense-in-depth payoff. Knowing the table name and the function names buys an attacker nothing.

### Rotating the key

Single transaction, in-place. Re-encrypt every row with a new CMK pulled from AKV:

```sql
BEGIN;

WITH old AS (SELECT current_setting('app.cmk_old') AS k),
     new AS (SELECT current_setting('app.cmk_new') AS k)
UPDATE my_app.customers c
SET email_enc       = pgp_sym_encrypt(pgp_sym_decrypt(c.email_enc,       (SELECT k FROM old)), (SELECT k FROM new)),
    ssn_enc         = pgp_sym_encrypt(pgp_sym_decrypt(c.ssn_enc,         (SELECT k FROM old)), (SELECT k FROM new)),
    card_number_enc = pgp_sym_encrypt(pgp_sym_decrypt(c.card_number_enc, (SELECT k FROM old)), (SELECT k FROM new));

COMMIT;
```

Then update the AKV secret to the new value. New sessions transparently pick up the new key on their next bootstrap.

---

## What this gets you

| Benefit | Why it matters |
|---|---|
| **Compromised credentials don't leak plaintext** | A leaked password for `demo_masked_user` only exposes masked values. No SSN. No full card. |
| **Internal threat resistance** | DBAs, SREs, and platform engineers reading rows directly see only `bytea`. Without the CMK they have no path to plaintext. |
| **Customer-facing apps become safe consumers** | Run your customer 360 / support / partner-portal app as a service principal in `pii_masked`. Even a full app compromise only leaks `a***@acme.com` and `XXX-XX-1234`. The apps that *do* see plaintext (fraud console, internal investigations) are much smaller, easier to audit, and run under tighter network controls. |
| **Per-column, per-role audit** | Postgres logs every `decrypt_full` call. Combined with Databricks audit on the AKV secret read, you get a complete chain: *"At 14:02, app X read the CMK; at 14:03, role Y decrypted 47 emails."* |
| **The CMK is yours, not Databricks'** | Stored in your AKV. Databricks never persists it. You can rotate, revoke, or expire it without involving anyone. |
| **One-statement key rotation** | No table downtime. No re-export/import. Just one `UPDATE` per rotation. |
| **Lakebase-native, no extra services** | Pure `pgcrypto` (already on Lakebase's [supported extensions list](https://docs.databricks.com/aws/en/oltp/projects/extensions)) + standard Postgres roles. No sidecar service, no separate KMS proxy. |
| **Composes with Lakehouse governance** | Lakebase is OLTP — keep BI on the Lakehouse side. If you sync the masked view to Delta via Lakeflow Connect Postgres ingestion, the *masked* values land in Unity Catalog and analysts query them through Power BI / Tableau / SQL warehouses. Apply UC column masks on top for a second layer of governance on the analytics side. |

---

## What this is *not*

Be honest with yourself about the threat model:

- **It's not TDE in the cryptographic sense.** It's application-managed envelope encryption, sitting on top of pgcrypto's symmetric AES.
- **It does not encrypt indexes or query plans.** If you index `email_enc`, you index ciphertext (which won't be useful for `LIKE` or range queries). For searchable encryption, look at deterministic encryption with `pgp_sym_encrypt` per-column-per-tenant or a proper SE library.
- **It does not protect against someone who legitimately holds the `pii_full_access` role.** That role is by definition allowed to see plaintext. Audit them, scope them tightly, rotate them often.
- **The CMK lives in session memory of a connected app for that connection's lifetime.** A heap dump of the app process exposes it. Use sealed memory if you're truly paranoid (rare), but the bigger lever is keeping app processes short-lived and audited.

---

## Wrapping up

Lakebase gives you a real Postgres with `pgcrypto` available. Databricks gives you AKV-backed secret scopes that make CMK management a one-line API call. Together, you can ship column-level encryption with dynamic masking in a few hundred lines of SQL — and a single Python helper for any app that talks to the database.

The mental model:

> **Encryption-at-rest** protects the **disk**.
> **Column-level encryption + masking** protects the **row** — from everyone except the role that's specifically allowed to see it.

Layer them. Audit both. Rotate both. Your future self (and your customers) will thank you.

---

*Want the full demo script that builds this end-to-end and runs all the bypass tests? It's [in the GitHub repo](https://github.com/nan-databricks/lakebase-field-level-encryption) — `scripts/cmk_column_masking_demo.py` plus a paste-and-go [`sql/setup.sql`](https://github.com/nan-databricks/lakebase-field-level-encryption/blob/main/sql/setup.sql).*

*Tags: #Databricks #Lakebase #Postgres #pgcrypto #DataMasking #ColumnLevelEncryption #CustomerManagedKey #AzureKeyVault #DataSecurity #PII*
