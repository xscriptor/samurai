# Authentication, User Management & Scheduled Scans

Operator guide for the features introduced in `2.6.0-alpha.1`. See [`CHANGELOG.md`](../../CHANGELOG.md) for the complete change list.

---

## 1. Overview

Starting with this release, Samurai is a multi-user system. Every REST endpoint and every WebSocket requires a valid JWT. Scans can now run on a cron schedule without an operator connected — a Celery worker executes them in the background and records results exactly like a manual run.

### Roles

| Role | Can read history | Can launch/cancel scans | Can manage schedules | Can manage users |
|---|---|---|---|---|
| `viewer` | yes | no | view only | no |
| `operator` | yes | yes | yes | no |
| `admin` | yes | yes | yes | yes |

Roles are enforced on the backend; the frontend hides actions the user cannot perform.

---

## 2. First-time setup

### 2.1 Environment variables

Set these before `docker compose up`. Defaults only make sense for local development.

```bash
# Use a random secret in any non-local environment
export JWT_SECRET_KEY=$(openssl rand -hex 64)

# Restrict CORS to the real frontend origin
export FRONTEND_ORIGIN=https://samurai.example.com

# Optional: change token lifetime (minutes)
export JWT_EXPIRE_MINUTES=60
```

### 2.2 Bring the stack up

```bash
docker compose up --build -d
```

This starts five services: `frontend`, `backend` (HTTP + WebSockets), `celery_worker`, `celery_beat`, `db` (Postgres), `redis`. On first boot the backend runs `alembic upgrade head` automatically, so migrations `0001` → `0003` apply in order.

### 2.3 Create the first admin

```bash
docker compose exec backend python -m app.scripts.create_admin \
    --username admin \
    --email admin@samurai.local \
    --password 'change-me-now'
```

Password is prompted interactively if you omit `--password`. `--role` defaults to `admin`; use `operator` or `viewer` for subsequent users (or create them from the UI — see §4).

### 2.4 Log in

Open http://localhost:4200. The app redirects to `/login`. Enter the credentials you just created.

---

## 3. Session management

### 3.1 Token lifecycle

- Successful login stores the JWT in `localStorage` under `samurai-auth-token`.
- The HTTP interceptor attaches `Authorization: Bearer <token>` to every request.
- WebSocket connections receive the token as `?token=<jwt>` — the backend validates it at `accept` before dispatching to the scan engine.
- A 401 response triggers automatic logout and redirect to `/login?redirect=<prev-url>`.
- Tokens expire after `JWT_EXPIRE_MINUTES` (default 60). There is no refresh token yet; the user must re-authenticate.

### 3.2 Logout

Click the red `LOGOUT` button in the sidebar user chip. The token is wiped from storage and you are sent back to `/login`.

### 3.3 Rate limiting

Login is capped at **5 attempts per minute** per caller (user id if known, otherwise IP). Exceeding the limit returns `429 Too Many Requests`. The backing store is Redis (shared across backend workers).

---

## 4. User management

Navigate to `/admin/users` (sidebar entry `99 // USERS (ADMIN)`, visible only when logged in as `admin`).

### 4.1 Create a user

Fill username (≥3 chars), email, password (≥8 chars), and role. Submit. The new user appears in the table below.

### 4.2 Change a role

Use the role dropdown on each row. Changes persist immediately. You cannot demote yourself out of the `admin` role.

### 4.3 Deactivate or reactivate

Click the `ACTIVE` / `INACTIVE` status badge. Inactive users keep their history but cannot log in. You cannot deactivate yourself.

### 4.4 Delete

Click `DELETE`. Confirm the prompt. The user row is removed. Any schedules they created retain `created_by_id = NULL` (foreign key is `SET NULL`). You cannot delete yourself.

---

## 5. Scheduled scans

Navigate to `/schedules` (sidebar entry `05 // SCHEDULES`). Available to any authenticated user for reading; `operator` and `admin` can create, edit, and delete.

### 5.1 Anatomy of a schedule

| Field | Purpose |
|---|---|
| Name | Human label shown in the list. |
| Scan type | `port_scan`, `web_recon`, or `vuln_crawl`. Drives which engine runs. |
| Target | Host/IP for `port_scan` and `web_recon`; full URL for `vuln_crawl`. Same validators as manual scans — arg-injection characters are rejected. |
| Cron | Standard 5-field cron expression (`minute hour day month weekday`). Validated with `croniter`. Preset buttons cover common cadences. |
| Config | Scan-type-specific JSON. Prefilled with sensible defaults when you switch type. |
| Enabled | Toggle. Disabled schedules keep their row but Beat skips them. |

### 5.2 Config cheatsheet

**`port_scan`**
```json
{ "profile": "quick", "timeout": 180, "web_scan": true, "max_pages": 12 }
```
`profile` ∈ `quick | balanced | deep | udp`.

**`web_recon`**
```json
{ "recon_types": "all", "timeout": 300 }
```
`recon_types` accepts a comma-separated list (`dns,subdomains,apis,headers,tech`) or `"all"`.

**`vuln_crawl`**
```json
{ "modules": "headers,cors,tls,xss,sqli,nuclei" }
```
`modules` accepts any subset of `tls,headers,cors,brute,sqli,sqlmap,xss,lfi,nuclei,playwright,api_security,auth_scan,js_secret` or `"all"`.

### 5.3 How execution works

1. `celery_beat` fires `dispatch_due_schedules` every 30 seconds.
2. The task queries `scheduled_scans` for rows where `is_enabled = true` and `next_run_at <= now()`.
3. For each match, `next_run_at` is advanced to the next cron occurrence **before** the job is enqueued. This prevents double-dispatch if the worker is slow.
4. `run_scheduled_scan(schedule_id)` on a worker loads the row, instantiates a `NullSink` (no WebSocket; progress goes to the worker log), and invokes the matching engine.
5. The engine creates the standard `Scan` + `Finding` records exactly like a manual run. The schedule's `last_run_at` and `last_scan_id` are updated.

Results appear under `/history` with the same target as any ad-hoc scan. Filter by `scan_type` or target to distinguish them.

### 5.4 Monitoring the workers

```bash
docker compose logs -f celery_beat
docker compose logs -f celery_worker
```

Typical healthy pattern:

```
celery_beat     | [2026-04-20 14:30:00,012: INFO/MainProcess] Scheduler: Sending due task dispatch-due-schedules
celery_worker   | [2026-04-20 14:30:00,240: INFO/MainProcess] Task app.tasks.dispatch_due_schedules received
celery_worker   | [2026-04-20 14:30:00,310: INFO/ForkPoolWorker-2] Dispatched schedule #1 (Nightly port scan — scanme)
celery_worker   | [2026-04-20 14:30:00,412: INFO/MainProcess] Task app.tasks.run_scheduled_scan received
celery_worker   | [2026-04-20 14:30:02,803: INFO/ForkPoolWorker-1] [schedule#1] [+] Starting nmap scan on target: scanme.nmap.org
```

### 5.5 Pausing vs. deleting

- **Pause**: click the `ENABLED` → `PAUSED` badge on the row. Row stays, Beat ignores it. Re-enable at any time.
- **Delete**: use the `DELETE` action. The row is removed; past scans produced by this schedule remain in `/history`.

---

## 6. Troubleshooting

**Login returns 401 even with correct credentials.**
Token expired or server restarted after you logged in — the dev fallback regenerates `JWT_SECRET_KEY` on each start, invalidating all existing tokens. Set `JWT_SECRET_KEY` in the environment to persist across restarts.

**`/admin/users` is missing from the sidebar.**
Only visible to `admin`. Check `auth.currentUser()?.role` in the browser console; if it is `viewer` or `operator`, the guard redirects to `/scanner`.

**Scheduled scan never runs.**
1. Check the schedule: `is_enabled = true`, `next_run_at` set, cron valid.
2. `docker compose logs celery_beat` should show `Scheduler: Sending due task dispatch-due-schedules` every 30s.
3. `docker compose ps` must show `celery_worker` and `celery_beat` as `running`.
4. If the worker is up but nothing dispatches, check the clock: `docker compose exec backend date -u` and confirm it matches your expectation. Cron and `next_run_at` are UTC.

**`psycopg2.OperationalError: role "postgres" does not exist` after changing env vars.**
Postgres only applies `POSTGRES_USER`/`POSTGRES_PASSWORD` on the initial volume. Nuke the volume if you changed credentials:
```bash
docker compose down -v
docker compose up --build
```
This deletes all scan history; create the admin again afterwards.

**Rate limit hit during legitimate testing.**
Log in once, then reuse the token. Or flush Redis:
```bash
docker compose exec redis redis-cli FLUSHDB
```

---

## 7. What comes next

See [`ROADMAP.md`](../../ROADMAP.md) and the "Known gaps" section in [`CHANGELOG.md`](../../CHANGELOG.md) for planned work: dashboard, scan diff, webhooks, SARIF export, refresh tokens, and the test suite.
