# Changelog

All notable changes to Samurai are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use semantic versioning.

## [2.6.0-alpha.1] — 2026-04-20

Major hardening + automation release. Introduces authentication, RBAC, rate
limiting, scheduled scans with a Celery-backed runner, and a user-management UI.

See [`docs/uses/authentication-and-automation.md`](docs/uses/authentication-and-automation.md) for the operator guide.

### Added

#### Authentication & authorization
- JWT-based login (`POST /api/auth/login`) with bcrypt-hashed passwords.
- `GET /api/auth/me` for session rehydration.
- Three-role RBAC: `admin`, `operator`, `viewer` enforced on REST and WebSockets.
- WebSocket auth via `?token=` query parameter, validated at `accept`.
- Frontend `authGuard`, `adminGuard`, HTTP interceptor (attaches `Bearer` token, logs out on 401).
- App shell with user chip, role badge, and logout.
- `python -m app.scripts.create_admin` CLI for bootstrapping the first admin.

#### User management (admin-only)
- `GET|POST|PATCH|DELETE /api/users` with self-protection (cannot demote, deactivate, or delete your own account).
- `/admin/users` page: create, change role, activate/deactivate, delete.

#### Rate limiting
- `slowapi` + Redis backend. `POST /api/auth/login` capped at 5/minute per caller.
- Key function prefers authenticated user id over remote IP.

#### Scheduled scans (Phase A: definitions)
- `ScheduledScan` model + Alembic migration `0003`.
- `GET|POST|PATCH|DELETE /api/schedules` with cron validation via `croniter`.
- Reuses anti-injection target validators for `port_scan`, `web_recon`, `vuln_crawl`.
- `/schedules` page: preset cron buttons, per-type config templates, toggle ENABLED/PAUSED, inline edit.

#### Scheduled scans (Phase B: runner)
- Celery worker + Celery Beat containers added to `docker-compose.yml`.
- `dispatch_due_schedules` (Beat, every 30s) finds overdue schedules, reschedules `next_run_at`, enqueues jobs.
- `run_scheduled_scan` (worker) executes the matching engine headlessly, persists `Scan`+`Finding`, updates `last_run_at`/`last_scan_id`.
- `ProgressSink` abstraction decouples scan engines from WebSocket so they run identically under HTTP or Celery.

#### Security & ops
- Target validators reject shell metacharacters, URLs where a host is expected, embedded credentials in URLs, and leading `-` (nmap arg injection).
- CORS origin restricted to `FRONTEND_ORIGIN` env var.
- Alembic migrations become the schema source of truth (`create_all` removed from startup).
- `JWT_SECRET_KEY`, `JWT_EXPIRE_MINUTES`, `FRONTEND_ORIGIN` wired through `docker-compose.yml`.

### Changed
- Frontend API URLs centralised through `ApiConfigService` (dev vs prod via `environments/`).
- Scan engines (`scanner.py`, `crawler.py`, `recon/orchestrator.py`) accept any `ProgressSink` — no breaking change for HTTP callers.
- Login now calls `/api/auth/me` on success so the sidebar user chip renders without a page reload.

### Fixed
- Circular dependency between `AuthService` and `ApiConfigService` resolved by moving token injection to the WS builder services.
- `bcrypt>=4.1` compatibility pinned to `bcrypt==4.0.1` to avoid the `__about__` probe crash in `passlib==1.7.4`.

### Known gaps (deferred)
- No dashboard aggregating risk across targets.
- No refresh tokens (single access token, 60 min).
- No scan diff between runs of the same target.
- No webhook/Slack notifications on scan completion.
- No SARIF export for CI integrations.
- Tests suite absent (non-scheduled target for Tranche 3).
