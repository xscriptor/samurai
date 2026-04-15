# Python Libraries Used in Samurai Backend

Last update: 2026-04-15

## Scope

This document lists the Python libraries used by the backend in `samurai/backend`, based on:

- `samurai/backend/requirements.txt`
- direct imports in `samurai/backend/**/*.py`
- runtime startup command in `samurai/backend/Dockerfile`

## Libraries in Direct Use

| Library | Version | Main Purpose | Where It Is Used |
|---|---:|---|---|
| fastapi | 0.105.0 | API framework, REST and WebSocket endpoints | `app/main.py`, `app/scanner.py`, `app/crawler.py`, `app/recon/logger.py`, `app/recon/orchestrator.py` |
| uvicorn[standard] | 0.24.0 | ASGI server used to run the API | `backend/Dockerfile` (`CMD ["uvicorn", ...]`) |
| SQLAlchemy | 2.0.23 | ORM, sessions, models, and engine | `app/database.py`, `app/models.py`, `app/main.py`, `app/scanner.py`, `app/crawler.py` |
| psycopg2-binary | 2.9.9 | PostgreSQL driver used by SQLAlchemy at runtime | `app/database.py` (PostgreSQL URL), SQLAlchemy runtime dependency |
| requests | 2.31.0 | Synchronous HTTP requests for scan/crawl probes | `app/scanner.py`, `app/crawler.py` |
| beautifulsoup4 | 4.12.2 | HTML parsing and form/DOM extraction | `app/scanner.py`, `app/crawler.py` |
| playwright | 1.52.0 | Headless browser runtime analysis for JS surface mapping | `app/crawler.py` (`from playwright.async_api import async_playwright`) |
| dnspython | 2.5.0 | DNS resolution for recon modules | `app/recon/modules/dns_enumerator.py`, `app/recon/modules/subdomain_enumerator.py` |
| httpx | 0.25.2 | Async HTTP client for recon modules | `app/recon/modules/api_discovery.py`, `app/recon/modules/security_headers.py`, `app/recon/modules/subdomain_enumerator.py`, `app/recon/modules/technology_stack.py` |
| tldextract | 5.1.1 | Registrable domain extraction for subdomain logic | `app/recon/modules/subdomain_enumerator.py` |

## Test/Utility Dependency (Not Pinned Directly)

| Library | Source | Purpose | Where It Is Used |
|---|---|---|---|
| websockets | Usually provided by `uvicorn[standard]` stack | WebSocket client for local backend tests | `backend/test_ws.py`, `backend/test_ws2.py` |

## Libraries Declared in requirements Without Current Direct Imports

The following libraries are present in `requirements.txt` but do not currently appear as direct imports in backend code:

- celery
- redis
- aiohttp
- cryptography
- python-whois
- certifi

Reasons:

- Evaluation of future implementations.
