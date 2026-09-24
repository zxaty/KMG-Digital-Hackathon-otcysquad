# 03. Test project map

Public repo (from the QR code): `github.com/zxaty/KMG-Digital-Hackathon-otcysquad`
(fork of `AlmasNUR/KMG-Digital-Hackathon`).

⚠️ This is the publicly accessible copy. The final grading copy
(reference version / version-with-violations) is prepared separately by
the organizer and may differ (ТЗ §5). Use this as: (a) stack/structure
reference, likely stable, (b) a training fixture to sanity-check that
our agent actually catches known-suspect patterns. **Don't hardcode line
numbers as ground truth** — the agent must re-analyze the real target
at run time.

## Stack

Django app (helpdesk fork) + `portal` app layer on top. SQLite, Waitress
WSGI, local self-signed TLS, whitenoise for static files.

## Repo layout

```
demodesk/config/
  settings.py   — Django config: cookie/TLS/HSTS flags, PASSWORD_HASHERS,
                  MIDDLEWARE, INSTALLED_APPS
  urls.py       — root routing (includes portal/urls)
portal/          — app-specific layer
  access.py      — role checks (administrator/operator), queryset filters
  audit.py        — audit log: event recording, ORM signals (create/
                    update/delete/permissions/login/logout/login_failed),
                    AESGCM payload encryption
  hashers.py       — custom Argon2 password hasher (cost/memory/parallelism)
  local_acl.py      — runtime dir permissions (chmod/Windows ACL) for
                      keys and logs
  views.py           — tickets, user management, CSV/JSON export,
                       token-based API
  urls.py            — full route list (below)
src/helpdesk/         — forked helpdesk library core
  models.py            — Ticket, Queue, FollowUp, TicketChange,
                         FollowUpAttachment, etc.
  views/staff.py, public.py, api.py, auth.py, kb.py, feeds.py, permissions.py
  serializers.py, validators.py, sanitize.py
  templates/, static/, templatetags/
docs/
  ТЗ_Хакатон.docx, Техническая_спецификация...docx, Состав_материалов.txt
README.md              — setup, seed accounts, "regulatory sources"
                          section (relevant to IB-06)
```

## Routes (`demodesk/config/urls.py` → `portal.views`)

```
/, /tickets/, /tickets/new/, /tickets/<id>/, /tickets/<id>/delete/  login_required
/tickets/bulk/            bulk_status     login_required + access.operator_required
/attachments/<id>/        attachment      login_required
/manage/*                 manage/*        access.manage_required (checks is_staff)
/exports/people.csv       export_csv      access.admin_required + audit.record  ✅
/exports/people.json      export_json     login_required ONLY — no admin_required,
                                           no audit.record
/api/token/                token_issue     login_required
/api/v1/tickets/[<id>/]    ticket_api      custom Bearer-token auth
/api/catalog/tickets/      catalog_api     require_GET, NO auth at all
/api/manage/queues/<id>/   queue_api       login_required
```

## Observations on the current public copy (training fixtures, not final verdicts)

Use these to test your own agent ("does it catch this?") — not as a
ready answer sheet for the actual defense.

1. **`export_json` (portal/views.py) — likely IB-08 violation.** Unlike
   `export_csv` (`@access.admin_required` + `audit.record(...)`),
   `export_json` returns the same PII set (login, name, email, role) to
   any **authenticated** user (`@login_required` only) and never writes
   an audit entry. Exactly the "sibling endpoint, lower standard"
   pattern flagged in `02-ib-requirements.md` § IB-08.

2. **`catalog_api` (portal/views.py) — likely IB-02 violation.**
   `/api/catalog/tickets/` has no `login_required` in urls.py and no
   token check inside the function (unlike `ticket_api`, which parses
   `Authorization: Bearer`). Returns all tickets, including
   `submitter_email` (PII), to unauthenticated callers.

3. **`demodesk/config/settings.py` — IB-03 check points.**
   `SESSION_COOKIE_SECURE = False`, `CSRF_COOKIE_SECURE = False`,
   `SECURE_SSL_REDIRECT = False`, `SECURE_HSTS_SECONDS = 0`. Could be
   explainable for a local dev stand (self-signed cert, 127.0.0.1 per
   README), but the agent must still flag these explicitly under IB-03
   with stated reasoning, not silently pass them.

4. **Positive examples (to calibrate against false positives):**
   - `portal/hashers.py` — Argon2 with explicit time/memory/parallelism
     params → correct IB-04 password handling.
   - `portal/audit.py` — AES-GCM encrypted events, atomic writes (tmp +
     rename) → looks like a correct IB-05/IB-07 base, **but** the agent
     must still verify coverage: are the `mutation`/`deletion` ORM
     signals actually wired to every model, or only some (cross-cutting
     check, see IB-07)?
   - `portal/access.py` — queryset filtering by role (`tickets()`,
     `queues()`) happens server-side → aligns with IB-01/IB-02 intent,
     but verify **all** views actually use these helpers rather than
     querying models directly.

## How the agent should build its own map at run time

Don't hardcode the file list above as ground truth. Each run:

1. Build a route/endpoint map by parsing the actual `urls.py`/equivalent.
2. Build a model/entity map for anything storing PII.
3. Re-cross-reference both against the 8 requirements — the final
   target's file layout may differ from this copy.

This doc accelerates orientation and gives a test fixture — it is not
the source of truth for the actual submission.
