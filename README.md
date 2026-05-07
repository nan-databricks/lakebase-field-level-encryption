# Lakebase Field-Level Encryption

> Column-level encryption + dynamic masking on **Databricks Lakebase** (managed Postgres) using `pgcrypto` and a **customer-managed key (CMK)** from Azure Key Vault / AWS KMS / GCP KMS.

![Architecture](blog/images/architecture.png?v=2)

## What this is

A reference implementation that protects PII in a Lakebase table so that:

- Data on disk and in backups is **bytea ciphertext** — useless to anyone who steals the file.
- A **`pii_full_access`** role sees plaintext via `customers_full`.
- A **`pii_masked`** role sees redacted strings (`a***@acme.com`, `XXX-XX-1234`, `************4242`) via `customers_masked`.
- The **CMK lives in Azure Key Vault** (or any KMS), is fetched per session by the app, and is never persisted in Postgres.
- The plaintext **never crosses a role boundary** inside the database — the masked role's decrypt path never returns the cleartext.

It's the "second layer" on top of platform encryption-at-rest. See [the blog post](blog/lakebase-column-masking-cmk.md) for the full why and the threat-model comparison vs. SQL Server Always Encrypted.

## Same row, two roles, two views

![Privileged vs masked output](blog/images/comparison.png?v=2)

## Repo layout

```
.
├── README.md                              # this file
├── requirements.txt                       # Python deps
├── blog/
│   ├── lakebase-column-masking-cmk.md     # the Medium-ready writeup
│   └── images/                            # architecture + screenshots
├── scripts/
│   └── cmk_column_masking_demo.py         # end-to-end runnable demo
├── sql/
│   └── setup.sql                          # paste-into-SQL-editor version
└── customer-pdf/
    ├── lakebase-field-level-encryption.pdf  # 1-page customer leave-behind
    ├── onepager.html                        # source (edit & regenerate)
    └── render_pdf.py                        # Playwright renderer
```

## Quick start

### Option A — paste-and-go in the Lakebase SQL Editor

1. Open the Lakebase SQL Editor on your project.
2. Paste [`sql/setup.sql`](sql/setup.sql) and run.
3. Insert a few rows:

   ```sql
   SELECT my_app.add_customer('Alice Anderson', 'alice@acme.com',  '123-45-6789', '4111111111111111');
   SELECT my_app.add_customer('Bob Brown',      'bob@globex.com',  '987-65-4321', '5500000000000004');
   ```

4. See the difference:

   ```sql
   SET ROLE demo_pii_user;
   SELECT * FROM my_app.customers_full;     -- plaintext

   RESET ROLE;
   SET ROLE demo_masked_user;
   SELECT * FROM my_app.customers_masked;   -- a***@acme.com, XXX-XX-6789, ...
   ```

### Option B — automated end-to-end demo from a Databricks App or CLI

```bash
pip install -r requirements.txt

# Update PROFILE / PROJECT / ENDPOINT in the script for your workspace
DATABRICKS_CONFIG_PROFILE=my-workspace python3 scripts/cmk_column_masking_demo.py
```

The script:

1. Creates the schemas, the encrypted table, the CMK vault, and both roles.
2. Inserts 4 sample customers.
3. Queries the table as `demo_pii_user` (sees plaintext).
4. Queries again as `demo_masked_user` (sees masked).
5. Runs four bypass attempts as the masked role — all are denied.
6. Rotates the CMK in place and re-queries to prove rows were re-encrypted under the new key.

## Bypass attempts — all blocked

![Bypass attempts](blog/images/bypass.png?v=2)

## On-prem encryption → Lakebase serving (recommended for PCI / PII)

The pattern in the rest of this repo (`pgcrypto` + CMK + role-gated views) decrypts inside Lakebase, which is the right fit for **operational scenarios where an authorized role legitimately needs to read plaintext** (fraud console, ops tooling, customer-360 view).

For **PCI cardholder data and high-sensitivity PII served to cloud workloads**, the stronger and more common bank pattern is:

> **Encrypt or HMAC-hash the value on-prem before it ever reaches the cloud. The CMK never leaves the on-prem HSM.**

Lakebase only ever stores `bytea` ciphertext. The cloud workload is then **out of PCI DSS § 3.5 / § 3.6 scope** for those columns — a major scope-reduction win in any QSA assessment.

![On-prem encryption to Lakebase serving](blog/images/onprem_encrypt_to_lakebase.png?v=1)

### How the flow maps end-to-end

| # | Component | Zone | What it does |
|---|---|---|---|
| 1 | Source system (core banking, CRM, card issuer) | On-prem PCI CDE | Holds plaintext PAN, name, national ID |
| 2 | Encryption / hashing service | On-prem PCI CDE | HMAC-SHA256 for lookup-only fields · AES-GCM (randomized) for fields that must be readable later · FPE / tokenization for PAN |
| 🔑 | On-prem HSM (Thales / Entrust / nCipher) | On-prem PCI CDE | CMK never leaves; CEKs are wrapped by CMK |
| 3 | Lakebase (Postgres) | Cloud | Stores `pan_ct bytea`, `pan_hmac bytea`, `name_ct bytea`, `last4 text` — workspace-CMK TDE on top |
| 4 | Serving / lookup app (Databricks App, FastAPI) | Cloud | Computes `HMAC(query_PAN)`, looks up by `pan_hmac`, returns ciphertext to caller — never holds CMK, never sees plaintext |
| 5 | Decryption service (return path) | On-prem PCI CDE | Receives ciphertext from cloud, unwraps with HSM, returns plaintext **inside the CDE only** |
| 6 | CSR / branch / call-centre app | On-prem PCI CDE | Authorized human reads full PAN inside on-prem network |
| 📱 | Customer-facing channel (mobile, web, partner API) | Cloud | Receives `last-4 only`, masked values, or status flags |

### What crosses the boundary

- **Allowed (cloud-bound):** AES-GCM ciphertext · HMAC index · `last4`
- **Allowed (on-prem-bound):** ciphertext rows for the return path
- **Never crosses:** CMK · CEK · plaintext PAN

### How this approach aligns with PCI DSS 4.0

| PCI DSS 4.0 control | What this architecture gives you |
|---|---|
| **§ 3.5.1** PAN unreadable wherever stored | ✅ Lakebase only stores `bytea` ciphertext / HMAC. Native requirement satisfied without relying on cloud TDE alone. |
| **§ 3.5.1.1** Hashes must use a keyed cryptographic hash | ✅ Use **HMAC-SHA256** with on-prem secret pepper — never plain SHA-256 (PAN keyspace is brute-forceable). |
| **§ 3.6** Cryptographic key management | ✅ CMK never leaves the on-prem HSM → cloud is **out of key-management scope**. The single biggest scope-reduction win. |
| **§ 3.7** Key lifecycle & rotation | ✅ Rotation happens on-prem; cloud just stores re-wrapped ciphertext. |
| **§ 4.2** Strong crypto for transmission | ✅ TLS 1.2+ to Lakebase by default · Private Link / VPC peering recommended. |
| **§ 7 / § 8** Least-privilege access to PAN | ✅ Even a cloud DBA querying the table sees ciphertext only; no Lakebase role can recover PAN. |
| **§ 3.3.1** Sensitive auth data must not be stored post-auth | ✅ CVV / CVV2 / track / PIN never leave on-prem; never written to Lakebase. |
| **§ 10** Audit trail of access | ✅ Lakebase Postgres audit logs + Databricks workspace audit logs + on-prem decrypt-service logs. |

### Choose the right primitive per column

```
Is this column ever shown back to a human or downstream system?
├── No  → HMAC-SHA256 on-prem with HSM key
│        (lookup works, value is unrecoverable)
│
└── Yes → Is this PAN / CVV?
         ├── CVV / track / PIN  → DO NOT STORE
         ├── PAN                → Tokenize on-prem (best)
         │                         OR FPE on-prem (if PAN-shape needed downstream)
         │                         OR AES-GCM + on-prem CEK + last4 in clear
         └── Other PII (name,
              email, address)   → AES-GCM (randomized) on-prem
                                  + optional HMAC sidecar for lookup/join
```

### What to avoid in the cloud zone

- ❌ Decrypt PAN inside the Databricks app — pulls cloud back into PCI § 3.5 / § 3.6 scope.
- ❌ Store CVV, CVV2, full track data, PIN or PIN block — PCI § 3.3.1 prohibits regardless of encryption.
- ❌ Use plain SHA-256 of PAN — brute-forceable; PCI § 3.5.1.1 requires a keyed hash.
- ❌ Sync the on-prem CMK into AKV / KMS to make decrypt easier — undoes the entire scope-reduction benefit.

The `pgcrypto` + role-gated views pattern in this repo is **complementary** to this on-prem-first design — use it for non-PCI columns where in-cloud business logic legitimately needs plaintext for an authorized role.

## How it differs from encryption-at-rest

![Encryption at rest vs column-level encryption](blog/images/at_rest_vs_column.png?v=2)

| Threat | Encryption at rest | Column-level encryption + masking |
|---|---|---|
| Stolen backup / disk image | Protected | Protected |
| Compromised application credential | Plaintext exposed | Only the role's view (mask or null) |
| Curious DBA reading rows | Plaintext exposed | Sees ciphertext only |
| Customer-facing app role compromised | Plaintext exposed | App's role gets masked values only |
| Audit / least-privilege controls | Per-disk, not per-column | Per-column, per-role, per-strategy |
| Key rotation | Re-encrypts the volume | In-place row-level re-encrypt in one `UPDATE` |

You want **both layers** — they protect different attackers.

## How this compares to TDE and SQL Server Always Encrypted

A common question: "isn't this the same as SQL Server Always Encrypted?" — not quite. The three approaches differ in **where the encryption happens** and therefore **what the database server is ever allowed to see**:

| | Where encrypt/decrypt runs | Server sees plaintext? | Server sees the key? | Defends against |
|---|---|---|---|---|
| **TDE / encryption-at-rest** <br>(Lakebase storage CMK, EBS, Azure SQL TDE) | Storage layer | **Yes**, always — disk is decrypted before the engine reads it | Yes (or KMS does it transparently) | Stolen disk / backup only |
| **Field-level encryption + masking** <br>(this repo: pgcrypto + CMK + role-gated views) | **Server**, inside `pgp_sym_decrypt` | **Briefly**, only during the function call | Yes, only while the function executes (CMK injected via session GUC) | Stolen disk · compromised app credential · curious DBA reading rows · over-broad role grants |
| **SQL Server Always Encrypted** | **Client driver** (.NET / JDBC / ODBC) | **Never** | Never — key lives in client-side AKV / cert store | All of the above **plus** a malicious DBA / cloud operator with full server access |

**The short version:**

- **TDE** → the *disk* is encrypted, but the engine and any authenticated user see plaintext.
- **Field-level (this repo)** → the *column* is encrypted, the server briefly handles the key so it can decrypt for authorized roles. Defends against compromised credentials and curious DBAs reading raw rows. Right tool for "support agent vs fraud analyst" scenarios on Lakebase.
- **Always Encrypted** → the *column* is encrypted, the server **never** has the key or the plaintext. Strongest threat model. Right tool when *"the cloud provider's DBA must never see this field, full stop"* is a hard requirement.

The closest equivalent to Always Encrypted on Postgres is **client-side encryption** — encrypt in the application before `INSERT`, decrypt after `SELECT`. Postgres only ever sees `bytea`. Works on any Postgres including Lakebase, but loses the in-database flexibility (no views, no aggregates, no `WHERE` on encrypted columns).

You can also **stack** these layers: enable TDE on the Lakebase storage layer (workspace CMK on AKV) **and** apply field-level encryption + masking on top. They protect different attackers.

## CMK from Azure Key Vault (or AWS KMS / GCP KMS)

The recommended app-side bootstrap:

```python
import psycopg
from databricks.sdk import WorkspaceClient

w = WorkspaceClient(profile="my-workspace")

# 1) Fetch the CMK from Azure Key Vault via Databricks Secret Scope (AKV-backed)
cmk = w.dbutils.secrets.get(scope="lakebase-cmk", key="lakebase-cmk")

# 2) Get a Lakebase OAuth token (1-hour expiry)
ep    = w.postgres.get_endpoint(name="projects/my-project/branches/production/endpoints/primary")
token = w.postgres.generate_database_credential(endpoint=ep.name).token
host  = ep.status.hosts.host

# 3) Connect and inject the CMK as a SESSION-LOCAL GUC (never persisted)
with psycopg.connect(
    host=host, dbname="databricks_postgres",
    user=w.current_user.me().user_name, password=token, sslmode="require",
) as conn, conn.cursor() as cur:
    cur.execute("SELECT set_config('app.cmk', %s, false);", (cmk,))
    cur.execute("SET ROLE demo_pii_user;")
    cur.execute("SELECT id, email, ssn FROM my_app.customers_full;")
    print(cur.fetchall())
```

For ad-hoc SQL Editor / break-glass access where a Python bootstrap isn't available, use a tiny scheduled Databricks Job to push the CMK into a locked-down `vault.keys` table (the variant in `scripts/cmk_column_masking_demo.py`).

> **Note on consumers.** Lakebase is OLTP. The clients of these masking views are **Databricks Apps**, microservices, and operational backends — *not* BI tools. For analytics on the same data, sync the *masked* view to Delta via Lakeflow Connect Postgres ingestion and apply Unity Catalog column masks on the Lakehouse side.

## Requirements

- Lakebase Autoscaling project (Postgres 16 or 17). [Supported extensions](https://docs.databricks.com/aws/en/oltp/projects/extensions) — `pgcrypto` is the only one we need.
- Databricks workspace with permissions to create Postgres roles in the project.
- Python 3.10+ for the demo script (`databricks-sdk` ≥ 0.81, `psycopg[binary]` ≥ 3.0).

## Reading order

1. [`blog/lakebase-column-masking-cmk.md`](blog/lakebase-column-masking-cmk.md) — the full writeup with the why, the threat model, and a comparison vs SQL Server Always Encrypted.
2. [`sql/setup.sql`](sql/setup.sql) — the SQL you'd paste into Lakebase SQL Editor.
3. [`scripts/cmk_column_masking_demo.py`](scripts/cmk_column_masking_demo.py) — a runnable, idempotent end-to-end demo with bypass tests.

## License

MIT — see [LICENSE](LICENSE) (or use freely; this is a reference pattern).
