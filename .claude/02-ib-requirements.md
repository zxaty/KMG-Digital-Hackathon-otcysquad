# 02. IB requirements — detection guidance

All 8 mandatory requirements from ТЗ §4.5. For each: meaning, what
counts as a violation, and what to look for. Framework-agnostic wording
(target is Django, but keep detection logic general).

IB-01, IB-02, IB-04, IB-07, IB-08 are partly/fully **cross-cutting** —
cannot be confirmed/denied from a single file.

---

## IB-01. Admin functionality access control

**Meaning:** admin functions restricted to role "administrator", checked
**server-side** on every request. Hiding UI elements client-side does
not satisfy this.

**Detect:**
- List every server-side route that manages users/roles/permissions/
  system settings/exports.
- For each: is there a server-side role check (decorator/middleware),
  not just template-level hiding?
- Watch for role checks that test the wrong thing (e.g. `is_staff`
  instead of `role == 'administrator'` — not equivalent if `is_staff`
  is also true for non-admins).
- Check built-in framework admin panel access restriction too.

**Scope:** partial cross-cutting — walk all write/manage endpoints.

---

## IB-02. Server-side session/token validation

**Meaning:** session/token validity checked server-side on **every**
request to protected endpoints, including APIs.

**Detect:**
- Enumerate all routes, including `api/...`.
- For each: is it wrapped by a server-side auth guard/decorator/
  middleware?
- API/JSON routes are the common blind spot — HTML pages get protected,
  a "catalog" or "public" API endpoint gets forgotten.
- Custom token schemes: verify signature/expiry/revocation checked on
  every request, not only at issuance.

**Scope:** fully cross-cutting — full route enumeration incl. all API
versions.

---

## IB-03. Data-in-transit protection

**Meaning:** client-server traffic over TLS ≥1.2 with strong cipher
suites only. Config allowing plaintext or weak/old TLS is a violation.

**Detect:**
- Session/CSRF cookie `Secure` flags, HTTP→HTTPS redirect, HSTS, min TLS
  version, cipher suite config.
- Flags like SSL-redirect disabled / secure-cookie disabled / HSTS=0 are
  always a check subject — report with explicit severity/context, never
  silently downgrade without stated justification.
- Deploy/CI config — any step publishing over plain HTTP.

---

## IB-04. Cryptographic protection of personal data at rest

**Meaning:** PII (full name, login, email, password) stored per СТ РК
1073-2007 crypto level. Passwords **only** via bcrypt/argon2/scrypt.
Plaintext or fast general-purpose hashes (MD5/SHA1/SHA256 without an
adaptive KDF) = violation.

**Detect:**
- Password hasher config — default hasher must be argon2/bcrypt/scrypt
  with non-trivial cost/time/memory params.
- Any legacy user-creation path bypassing the standard hashing
  (direct password write, custom save()).
- How non-password PII is stored — field/DB/file-level encryption, or
  plaintext.
- Cross-check with IB-05 (logs) and IB-08 (exports) for PII leakage —
  these overlap but are scored as separate violations.

---

## IB-05. Local application log protection

**Meaning:** local logs encrypted at rest, protected from user
tampering **before** being sent to the server.

**Detect:**
- Locate the logging/audit module.
- On-disk payload encrypted (e.g. AEAD like AES-GCM) before write?
- Log directory/file permissions restrict a normal OS user from
  read/modify (chmod/ACL)?
- Atomic writes (temp file + rename) to avoid a tamper window?
- If logs are later "received" server-side: separate pending/received
  states with different permissions (pending = fewer rights)?

**Scope:** not cross-cutting, but usually spans 2 modules (log writer +
directory permission manager).

---

## IB-06. Regulatory references in project documentation

**Meaning:** README/ТЗ must reference: Law on Cybersecurity
(24.11.2015 №418-V), Law on Personal Data (21.05.2013 №94-V),
Government resolution №832 (20.12.2016), СТ РК ISO/IEC 27001-2023,
СТ РК ISO/IEC 27002-2023, СТ РК 1073-2007. No actual certification
required — only presence of references.

**Detect:**
- Check README and any `docs/` files for a regulatory-sources section;
  match the list above.
- Violation = missing reference to any one act, or section absent
  entirely.

---

## IB-07. User action & DB event logging (CROSS-CUTTING)

**Meaning:** a single unified user-action log + DB event log covering
**the whole project**, not one function/module. Partial coverage
(one entity only) = violation.

**Detect:**
- Locate the central logging mechanism (usually ORM signals/middleware/
  framework-level decorators, not scattered ad-hoc `log.info()` calls).
- Check **coverage**: is the central mechanism wired to **all**
  data-mutating models/entities, or only some? Enumerate all project
  models and cross-check.
- Are login/logout/failed-login events captured too?
- DB-level events checked separately from app-level events — ТЗ
  requires both (or one unified log covering both layers).

**Highest-leverage requirement for the 50%-weighted detection score and
the 5%-weighted completeness score** — agents that only diff-scan fail
this one specifically.

---

## IB-08. PII export control

**Meaning:** PII exports restricted to role "administrator" **and**
every export logged in the audit trail. Violation = missing role check
OR missing audit entry (or both).

**Detect:**
- Find every export/download endpoint (CSV, JSON, PDF, print) that
  returns PII (email, full name, phone, etc.).
- For **each**, check both independently:
  1. Server-side role check for "administrator" specifically (not just
     "any authenticated user" — `login_required` ≠ `role == admin`).
  2. Audit-log write inside that same handler.
- **Common bug pattern:** one export endpoint (e.g. CSV) done correctly
  with role check + audit; a sibling endpoint with the same data in a
  different format (e.g. JSON) done to a lower standard — missing role
  check and/or audit. Check **every** export route individually, don't
  generalize from the first one found.

---

## Summary table

| Req | Cross-cutting? | Needs full-project walk |
|---|---|---|
| IB-01 | partial | all admin/manage routes |
| IB-02 | yes | all routes incl. API |
| IB-03 | no | config (usually 1-2 files) |
| IB-04 | partial | hasher config + all user-creation/PII-storage points |
| IB-05 | no | logging module + permissions |
| IB-06 | no | docs (README, docs/) |
| IB-07 | **yes, explicit in ТЗ** | all models/entities |
| IB-08 | partial | every export endpoint separately |

4 of 8 requirements are physically unverifiable from one file or a
diff — this is exactly why ТЗ §4.4.1 mandates whole-project analysis.
