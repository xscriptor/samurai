import asyncio
import base64
import requests
import ssl
import socket
import shutil
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fastapi import WebSocket
from sqlalchemy.orm import Session
from . import models
from .progress import ProgressSink

# Configuración de payloads de Prueba
SENSITIVE_PATHS = [
    '/.env', 
    '/.git/config', 
    '/requirements.txt', 
    '/api/v1/', 
    '/config.php'
]
XSS_PAYLOADS = ["<script>alert(1)</script>", "javascript:alert(1)"]
SQLI_PAYLOADS = ["' OR 1=1--", "'; DROP TABLE users--"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../windows/win.ini"]
JS_ENDPOINT_PATTERNS = [
    r"fetch\(\s*['\"]([^'\"]+)['\"]",
    r"axios\.(?:get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]",
    r"open\(\s*['\"][A-Z]+['\"]\s*,\s*['\"]([^'\"]+)['\"]",
    r"['\"](/api/[^'\"\s]+)['\"]",
]

API_DISCOVERY_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui",
    "/swagger-ui/",
    "/api-docs",
    "/graphql",
    "/actuator",
    "/actuator/health",
    "/api",
    "/api/v1",
]

AUTH_PROTECTED_CANDIDATES = [
    "/admin",
    "/dashboard",
    "/settings",
    "/profile",
    "/api/admin",
    "/api/private",
    "/internal",
]

JS_SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY_ID", r"AKIA[0-9A-Z]{16}"),
    ("GITHUB_TOKEN", r"ghp_[A-Za-z0-9]{36}"),
    ("STRIPE_LIVE_KEY", r"sk_live_[0-9a-zA-Z]{16,}"),
    ("JWT_TOKEN", r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),
    ("GENERIC_API_KEY", r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{12,}['\"]"),
    ("PRIVATE_KEY_BLOCK", r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
]


def _parse_nuclei_severity(line: str) -> str:
    match = re.search(r"\[(critical|high|medium|low|info)\]", line, re.IGNORECASE)
    if not match:
        return "medium"
    return match.group(1).lower()


def _extract_js_endpoints(script_content: str):
    discovered = set()
    for pattern in JS_ENDPOINT_PATTERNS:
        for value in re.findall(pattern, script_content, flags=re.IGNORECASE):
            if value and len(value) < 240:
                discovered.add(value.strip())
    return discovered


def _build_auth_headers(auth_context: dict | None):
    if not auth_context:
        return {}

    headers = {}

    bearer = (auth_context.get("bearer") or "").strip()
    user = (auth_context.get("user") or "").strip()
    password = auth_context.get("password") or ""
    cookie = (auth_context.get("cookie") or "").strip()
    mode = (auth_context.get("mode") or "bearer_first").strip().lower()

    if mode == "basic_first":
        if user:
            credentials = f"{user}:{password}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode("utf-8")
        elif bearer:
            headers["Authorization"] = f"Bearer {bearer}"
    else:
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        elif user:
            credentials = f"{user}:{password}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode("utf-8")

    if cookie:
        headers["Cookie"] = cookie

    return headers

async def audit_ssl(target_url: str, scan_record: models.Scan, websocket: ProgressSink, db: Session):
    parsed = urlparse(target_url)
    domain = parsed.netloc
    if ":" in domain:
        domain = domain.split(":")[0]
        
    await websocket.send_text(f"[*] Auditing TLS/SSL Configuration for {domain}...")
    try:
        def get_ssl_info():
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.version(), ssock.cipher()
                    
        version, cipher = await asyncio.to_thread(get_ssl_info)
        await websocket.send_text(f"    [INFO] SSL/TLS Version: {version}")
        await websocket.send_text(f"    [INFO] Cipher Suite: {cipher[0]}")
        
        if version in ["TLSv1", "TLSv1.1", "SSLv3"]:
            finding = models.Finding(
                scan_id=scan_record.id, severity="high", finding_type="WEAK_TLS_VERSION",
                description=f"Server supports obsolete TLS version: {version}",
                cvss_score="7.5", poc_payload=f"Domain: {domain}:443\nVersion Negotiated: {version}"
            )
            db.add(finding)
            db.commit()
            await websocket.send_text(f"    [!] VULNERABILITY DETECTED: Obsolete SSL/TLS ({version})")
    except Exception as e:
        await websocket.send_text(f"    [-] SSL/TLS Audit Failed or No HTTPS.")

def audit_headers_and_fingerprint(response, current_url, link_id, scan_id, websocket, db, vulns_found, messages):
    headers = response.headers
    
    server = headers.get("Server")
    x_powered = headers.get("X-Powered-By")
    if server or x_powered:
        messages.append(f"    [INFO] Fingerprint: Server={server}, X-Powered={x_powered}")
        
    security_headers = {
        "Strict-Transport-Security": ("medium", "Missing HSTS", "4.3"),
        "Content-Security-Policy": ("medium", "Missing CSP", "4.3"),
        "X-Content-Type-Options": ("low", "Missing X-Content-Type-Options", "2.6")
    }
    
    for header, (sev, type_, cvss) in security_headers.items():
        lower_headers = [k.lower() for k in headers.keys()]
        if header.lower() not in lower_headers:
            finding = models.Finding(
                scan_id=scan_id, link_id=link_id, severity=sev, finding_type=type_,
                description=f"{header} header is missing from the response.",
                cvss_score=cvss, poc_payload=f"URL: {current_url}\nMissing HTTP Header: {header}"
            )
            db.add(finding)
            vulns_found[0] += 1
            messages.append(f"    [!] VULNERABILITY DETECTED: {type_}")
            
    # Cookies
    set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
    if set_cookie:
        cookie = set_cookie.lower()
        missing_flags = []
        if "httponly" not in cookie: missing_flags.append("HttpOnly")
        if "secure" not in cookie: missing_flags.append("Secure")
        if "samesite" not in cookie: missing_flags.append("SameSite")
        
        if missing_flags:
            finding = models.Finding(
                scan_id=scan_id, link_id=link_id, severity="medium", finding_type="INSECURE_COOKIE",
                description=f"Cookie is missing critical security flags: {', '.join(missing_flags)}",
                cvss_score="5.3", poc_payload=f"URL: {current_url}\nSet-Cookie: {set_cookie}"
            )
            db.add(finding)
            vulns_found[0] += 1
            messages.append(f"    [!] VULNERABILITY DETECTED: Insecure Cookie Flags")

async def test_cors(current_url, link_id, scan_id, websocket, db, vulns_found):
    try:
        res = await asyncio.to_thread(requests.get, current_url, headers={"Origin": "https://evil.com"}, timeout=3)
        if res.headers.get("Access-Control-Allow-Origin") == "https://evil.com" or res.headers.get("Access-Control-Allow-Origin") == "*":
            finding = models.Finding(
                scan_id=scan_id, link_id=link_id, severity="high", finding_type="CORS_MISCONFIGURATION",
                description="Server implicitly trusts arbitrary cross-origin requests.",
                cvss_score="6.5", poc_payload=f"GET {current_url}\nOrigin: https://evil.com\n\nResponse:\nAccess-Control-Allow-Origin: {res.headers.get('Access-Control-Allow-Origin')}"
            )
            db.add(finding)
            db.commit()
            vulns_found[0] += 1
            await websocket.send_text(f"    [!] HIGH: CORS Misconfiguration detected.")
    except Exception:
        pass

async def active_fuzz_forms(soup, current_url, link_id, scan_id, websocket, db, vulns_found, active_modules):
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        form_url = urljoin(current_url, action)
        
        inputs = form.find_all("input")
        input_names = [i.get("name") for i in inputs if i.get("name")]
        
        if not input_names:
            continue
            
        await websocket.send_text(f"    [*] Fuzzing form at {form_url} with {len(input_names)} inputs...")
        
        # Test SQLi
        if "sqli" in active_modules or "all" in active_modules:
            for payload in SQLI_PAYLOADS:
                data = {name: payload for name in input_names}
                try:
                    if method == "post":
                        res = await asyncio.to_thread(requests.post, form_url, data=data, timeout=3)
                    else:
                        res = await asyncio.to_thread(requests.get, form_url, params=data, timeout=3)
                    
                    if res.status_code == 500 or "syntax error" in res.text.lower() or "mysql" in res.text.lower():
                        finding = models.Finding(
                            scan_id=scan_id, link_id=link_id, severity="critical", finding_type="SQL_INJECTION",
                            description=f"Possible SQL Injection successfully forced a 500 Server Error or Syntax Leak.",
                            cvss_score="9.8", poc_payload=f"Method: {method.upper()}\nURL: {form_url}\nPayload Data: {data}"
                        )
                        db.add(finding)
                        db.commit()
                        vulns_found[0] += 1
                        await websocket.send_text(f"    [!] CRITICAL: SQLi Anomaly Detected via 500 status.")
                        break
                except Exception:
                    pass
                    
        # Test XSS
        if "xss" in active_modules or "all" in active_modules:
            for payload in XSS_PAYLOADS:
                data = {name: payload for name in input_names}
                try:
                    if method == "post":
                        res = await asyncio.to_thread(requests.post, form_url, data=data, timeout=3)
                    else:
                        res = await asyncio.to_thread(requests.get, form_url, params=data, timeout=3)
                    
                    if payload in res.text:
                        finding = models.Finding(
                            scan_id=scan_id, link_id=link_id, severity="high", finding_type="REFLECTED_XSS",
                            description=f"Payload was reflected unmodified in application response.",
                            cvss_score="6.1", poc_payload=f"Method: {method.upper()}\nURL: {form_url}\nPayload: {data}\nResponse Reflection: {payload}"
                        )
                        db.add(finding)
                        db.commit()
                        vulns_found[0] += 1
                        await websocket.send_text(f"    [!] HIGH: Reflected XSS vulnerability confirmed.")
                        break
                except Exception:
                    pass

        # Test LFI
        if "lfi" in active_modules or "all" in active_modules:
            for payload in LFI_PAYLOADS:
                data = {name: payload for name in input_names}
                try:
                    if method == "post":
                        res = await asyncio.to_thread(requests.post, form_url, data=data, timeout=3)
                    else:
                        res = await asyncio.to_thread(requests.get, form_url, params=data, timeout=3)
                    
                    if "root:x:0:0" in res.text.lower() or "[extensions]" in res.text.lower():
                        finding = models.Finding(
                            scan_id=scan_id, link_id=link_id, severity="critical", finding_type="LOCAL_FILE_INCLUSION",
                            description=f"Server returned contents of sensitive system files when traversing paths.",
                            cvss_score="8.6", poc_payload=f"Method: {method.upper()}\nURL: {form_url}\nPayload Data: {data}"
                        )
                        db.add(finding)
                        db.commit()
                        vulns_found[0] += 1
                        await websocket.send_text(f"    [!] CRITICAL: LFI Directory Traversal Detected.")
                        break
                except Exception:
                    pass

async def fuzz_paths(target_url, domain, scan_id, websocket, db, vulns_found):
    await websocket.send_text(f"[*] Fuzzing exposed sensitive paths...")
    base_url = target_url
    
    for path in SENSITIVE_PATHS:
        probe_url = urljoin(base_url, path)
        try:
            res = await asyncio.to_thread(requests.get, probe_url, timeout=3)
            if res.status_code == 200 and "not found" not in res.text.lower() and "<html" not in res.text[:20].lower():
                finding = models.Finding(
                    scan_id=scan_id, link_id=None, severity="critical", finding_type="EXPOSED_SENSITIVE_FILE",
                    description=f"Sensitive file or path {path} is publicly accessible.",
                    cvss_score="7.5", poc_payload=f"GET {probe_url} (HTTP 200 OK)\n\nPreview:\n{res.text[:100]}..."
                )
                db.add(finding)
                db.commit()
                vulns_found[0] += 1
                await websocket.send_text(f"    [!] CRITICAL DETECTED: Exposed configuration at {path}")
        except Exception:
            pass


async def run_sqlmap_module(target_url, scan_id, websocket, db, vulns_found):
    await websocket.send_text("[*] SQLMap module enabled. Running automated SQLi verification...")

    if not shutil.which("sqlmap"):
        await websocket.send_text("    [-] SQLMap binary not found. Skipping SQLMap module.")
        return

    process = await asyncio.create_subprocess_exec(
        "sqlmap", "-u", target_url,
        "--batch", "--level", "1", "--risk", "1", "--threads", "2", "--smart",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )

    confirmed_sqli = False
    indicator_line = ""
    streamed_lines = 0

    if process.stdout:
        while True:
            line = await process.stdout.readline()
            if not line:
                break

            text_line = line.decode("utf-8", errors="ignore").rstrip()
            if not text_line:
                continue

            if streamed_lines < 30:
                await websocket.send_text(f"    [SQLMAP] {text_line}")
                streamed_lines += 1

            lower = text_line.lower()
            if not confirmed_sqli and (
                "is vulnerable" in lower
                or "sql injection" in lower
                or "parameter" in lower and "injectable" in lower
            ):
                confirmed_sqli = True
                indicator_line = text_line

    await process.wait()

    if confirmed_sqli:
        finding = models.Finding(
            scan_id=scan_id,
            link_id=None,
            severity="critical",
            finding_type="SQLMAP_CONFIRMED_SQLI",
            description="SQLMap reported a potential injectable parameter on the target.",
            cvss_score="9.8",
            poc_payload=f"Target: {target_url}\nIndicator: {indicator_line}"
        )
        db.add(finding)
        db.commit()
        vulns_found[0] += 1
        await websocket.send_text("    [!] CRITICAL: SQLMap confirmed a probable SQL Injection vector.")
    else:
        await websocket.send_text("    [i] SQLMap did not confirm SQLi on this run.")


async def run_nuclei_module(target_url, scan_id, websocket, db, vulns_found):
    await websocket.send_text("[*] Nuclei module enabled. Running template-based checks...")

    if not shutil.which("nuclei"):
        await websocket.send_text("    [-] Nuclei binary not found. Skipping Nuclei module.")
        return

    process = await asyncio.create_subprocess_exec(
        "nuclei", "-u", target_url,
        "-severity", "critical,high,medium,low,info",
        "-silent",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )

    match_count = 0

    if process.stdout:
        while True:
            line = await process.stdout.readline()
            if not line:
                break

            text_line = line.decode("utf-8", errors="ignore").rstrip()
            if not text_line:
                continue

            await websocket.send_text(f"    [NUCLEI] {text_line}")

            if match_count >= 20:
                continue

            severity = _parse_nuclei_severity(text_line)
            finding = models.Finding(
                scan_id=scan_id,
                link_id=None,
                severity=severity,
                finding_type="NUCLEI_TEMPLATE_MATCH",
                description="Nuclei reported a template match on the target.",
                cvss_score=None,
                poc_payload=text_line
            )
            db.add(finding)
            match_count += 1

    await process.wait()

    if match_count > 0:
        db.commit()
        vulns_found[0] += match_count
        await websocket.send_text(f"    [!] Nuclei generated {match_count} persisted findings.")
    else:
        await websocket.send_text("    [i] Nuclei did not report actionable matches.")


async def run_api_security_module(target_url, scan_id, websocket, db, vulns_found):
    await websocket.send_text("[*] API Security module enabled. Probing common API exposure surfaces...")

    findings_created = 0
    for path in API_DISCOVERY_PATHS:
        probe_url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
        try:
            res = await asyncio.to_thread(requests.get, probe_url, timeout=4)
        except Exception:
            continue

        body_preview = (res.text or "")[:300].lower()
        if res.status_code == 200 and any(k in body_preview for k in ["openapi", "swagger", "graphql", "actuator", "paths"]):
            sev = "high" if "openapi" in body_preview or "swagger" in body_preview else "medium"
            finding = models.Finding(
                scan_id=scan_id,
                link_id=None,
                severity=sev,
                finding_type="API_DOCS_OR_SCHEMA_EXPOSED",
                description="Potentially sensitive API documentation or schema endpoint is publicly accessible.",
                cvss_score="6.5" if sev == "high" else "4.8",
                poc_payload=f"GET {probe_url} -> HTTP {res.status_code}\nPreview: {body_preview[:200]}"
            )
            db.add(finding)
            findings_created += 1
            await websocket.send_text(f"    [!] {sev.upper()}: API exposure detected at {path}")

        allow_header = (res.headers.get("Allow") or "").upper()
        if res.status_code in (200, 204) and any(m in allow_header for m in ["PUT", "DELETE", "PATCH"]):
            finding = models.Finding(
                scan_id=scan_id,
                link_id=None,
                severity="medium",
                finding_type="RISKY_HTTP_METHODS_EXPOSED",
                description="Endpoint advertises potentially risky HTTP methods without prior auth context.",
                cvss_score="5.3",
                poc_payload=f"URL: {probe_url}\nAllow: {allow_header}"
            )
            db.add(finding)
            findings_created += 1
            await websocket.send_text(f"    [!] MEDIUM: Risky methods exposed at {path}")

    if findings_created:
        db.commit()
        vulns_found[0] += findings_created
    else:
        await websocket.send_text("    [i] API Security module did not detect high-confidence exposures.")


async def run_authenticated_scan_module(target_url, scan_id, websocket, db, vulns_found, auth_context=None):
    await websocket.send_text("[*] Authenticated Scan module enabled. Testing access control boundaries...")

    open_sensitive = []
    guarded_sensitive = []
    authenticated_access = []
    auth_headers = _build_auth_headers(auth_context)

    has_auth_context = bool(auth_headers)
    if has_auth_context:
        await websocket.send_text("    [i] Auth context provided. Running comparative auth/non-auth route probing.")
    else:
        await websocket.send_text("    [i] No auth context provided. Running boundary-only checks.")

    for path in AUTH_PROTECTED_CANDIDATES:
        probe_url = urljoin(target_url.rstrip('/') + '/', path.lstrip('/'))
        try:
            res = await asyncio.to_thread(requests.get, probe_url, timeout=4, allow_redirects=False)
        except Exception:
            continue

        if res.status_code in (401, 403):
            guarded_sensitive.append((probe_url, res.status_code))
            continue

        if res.status_code in (200, 302):
            open_sensitive.append((probe_url, res.status_code))

        if has_auth_context:
            try:
                auth_res = await asyncio.to_thread(
                    requests.get,
                    probe_url,
                    timeout=4,
                    allow_redirects=False,
                    headers=auth_headers
                )
                if auth_res.status_code in (200, 302):
                    authenticated_access.append((probe_url, auth_res.status_code))
            except Exception:
                pass

    findings_created = 0

    if open_sensitive:
        sample = open_sensitive[:6]
        finding = models.Finding(
            scan_id=scan_id,
            link_id=None,
            severity="high",
            finding_type="MISSING_AUTHORIZATION_BOUNDARY",
            description="Potentially sensitive routes are reachable without explicit authentication challenge.",
            cvss_score="7.1",
            poc_payload="\n".join([f"GET {url} -> HTTP {code}" for url, code in sample])
        )
        db.add(finding)
        findings_created += 1
        await websocket.send_text(f"    [!] HIGH: {len(open_sensitive)} sensitive route(s) reachable without auth challenge.")

    if guarded_sensitive:
        sample = guarded_sensitive[:6]
        finding = models.Finding(
            scan_id=scan_id,
            link_id=None,
            severity="info",
            finding_type="AUTH_GUARD_PRESENT",
            description="Sensitive routes responded with authentication/authorization challenge.",
            cvss_score=None,
            poc_payload="\n".join([f"GET {url} -> HTTP {code}" for url, code in sample])
        )
        db.add(finding)
        findings_created += 1
        await websocket.send_text("    [i] Authenticated boundaries detected on sensitive routes.")

    if has_auth_context and authenticated_access:
        sample = authenticated_access[:6]
        finding = models.Finding(
            scan_id=scan_id,
            link_id=None,
            severity="info",
            finding_type="AUTH_CONTEXT_VALIDATED_ACCESS",
            description="Provided auth context reached protected routes successfully.",
            cvss_score=None,
            poc_payload="\n".join([f"AUTH GET {url} -> HTTP {code}" for url, code in sample])
        )
        db.add(finding)
        findings_created += 1
        await websocket.send_text("    [i] Authenticated context validated against sensitive endpoints.")

    if findings_created:
        db.commit()
        vulns_found[0] += findings_created
    else:
        await websocket.send_text("    [i] Authenticated Scan module did not produce findings.")


async def inspect_js_secrets(soup, current_url, link_id, scan_id, websocket, db, vulns_found):
    await websocket.send_text("    [*] JS Secret Analysis: scanning inline and referenced scripts...")

    findings = []

    def collect_matches(content: str, origin: str):
        for name, pattern in JS_SECRET_PATTERNS:
            for match in re.findall(pattern, content):
                token = match if isinstance(match, str) else str(match)
                redacted = token[:6] + "..." + token[-4:] if len(token) > 14 else token
                findings.append((name, origin, redacted))
                if len(findings) >= 12:
                    return

    for script in soup.find_all("script"):
        inline_js = script.text or ""
        if inline_js.strip():
            collect_matches(inline_js, f"inline:{current_url}")
            if len(findings) >= 12:
                break

        script_src = script.get("src")
        if not script_src or len(findings) >= 12:
            continue

        script_url = urljoin(current_url, script_src)
        try:
            res = await asyncio.to_thread(requests.get, script_url, timeout=4)
            if res.status_code == 200 and "javascript" in (res.headers.get("Content-Type", "").lower() or ""):
                collect_matches(res.text or "", script_url)
        except Exception:
            continue

    if findings:
        unique = []
        seen = set()
        for item in findings:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)

        payload_lines = [f"{name} @ {origin} => {secret}" for name, origin, secret in unique[:10]]
        finding = models.Finding(
            scan_id=scan_id,
            link_id=link_id,
            severity="high",
            finding_type="JS_SECRET_LEAK",
            description="Potential secret/token material was detected in JavaScript sources.",
            cvss_score="7.0",
            poc_payload="\n".join(payload_lines)
        )
        db.add(finding)
        db.commit()
        vulns_found[0] += 1
        await websocket.send_text(f"    [!] HIGH: JS Secret Analysis detected {len(unique)} potential secret artifact(s).")
    else:
        await websocket.send_text("    [i] JS Secret Analysis found no high-confidence secret patterns.")


async def inspect_playwright_surface(soup, current_url, link_id, scan_id, websocket, db, vulns_found):
    script_endpoints = set()
    internal_refs = set()
    network_endpoints = set()

    await websocket.send_text("    [*] PLAYWRIGHT: Launching headless browser for JS/runtime inspection...")

    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            def on_request(request):
                network_endpoints.add(request.url)

            page.on("request", on_request)

            try:
                await page.goto(current_url, wait_until="networkidle", timeout=12000)
            except Exception:
                await websocket.send_text("    [-] PLAYWRIGHT: Navigation timeout; collecting partial runtime telemetry.")

            runtime_html = await page.content()
            runtime_soup = BeautifulSoup(runtime_html, 'html.parser')

            for script in runtime_soup.find_all("script"):
                script_content = script.text or ""
                if script_content.strip():
                    extracted = _extract_js_endpoints(script_content)
                    for endpoint in extracted:
                        normalized = urljoin(current_url, endpoint) if endpoint.startswith("/") else endpoint
                        script_endpoints.add(normalized)

            await context.close()
            await browser.close()
    except Exception:
        await websocket.send_text("    [-] PLAYWRIGHT runtime unavailable. Falling back to static JS analysis.")

    for script in soup.find_all("script"):
        script_src = script.get("src")
        if script_src:
            absolute = urljoin(current_url, script_src)
            if "/api/" in absolute or any(k in absolute.lower() for k in ["graphql", "admin", "debug", "internal", "actuator"]):
                script_endpoints.add(absolute)
            if any(k in absolute.lower() for k in ["admin", "debug", "internal", "actuator"]):
                internal_refs.add(absolute)

        script_content = script.text or ""
        if not script_content.strip():
            continue

        extracted = _extract_js_endpoints(script_content)
        for endpoint in extracted:
            normalized = urljoin(current_url, endpoint) if endpoint.startswith("/") else endpoint
            script_endpoints.add(normalized)
            lowered = normalized.lower()
            if any(k in lowered for k in ["admin", "debug", "internal", "actuator"]):
                internal_refs.add(normalized)

    for net_url in network_endpoints:
        lowered = net_url.lower()
        if "/api/" in lowered or any(k in lowered for k in ["graphql", "admin", "debug", "internal", "actuator"]):
            script_endpoints.add(net_url)
        if any(k in lowered for k in ["admin", "debug", "internal", "actuator"]):
            internal_refs.add(net_url)

    if script_endpoints:
        sample = sorted(script_endpoints)[:12]
        finding = models.Finding(
            scan_id=scan_id,
            link_id=link_id,
            severity="medium",
            finding_type="PLAYWRIGHT_JS_SURFACE",
            description=f"JavaScript endpoint surface discovered ({len(script_endpoints)} references).",
            cvss_score="4.8",
            poc_payload=f"Source URL: {current_url}\nDiscovered Endpoints:\n- " + "\n- ".join(sample)
        )
        db.add(finding)
        db.commit()
        vulns_found[0] += 1
        await websocket.send_text(f"    [!] PLAYWRIGHT: JS surface mapped ({len(script_endpoints)} references).")

    if internal_refs:
        sample_sensitive = sorted(internal_refs)[:8]
        finding = models.Finding(
            scan_id=scan_id,
            link_id=link_id,
            severity="high",
            finding_type="POTENTIAL_INTERNAL_API_EXPOSURE",
            description="Potential internal/admin API references found in client-side scripts.",
            cvss_score="6.4",
            poc_payload=f"Source URL: {current_url}\nSensitive References:\n- " + "\n- ".join(sample_sensitive)
        )
        db.add(finding)
        db.commit()
        vulns_found[0] += 1
        await websocket.send_text(f"    [!] HIGH: Potential internal endpoint references were exposed in JS.")


async def perform_crawl(target_url: str, modules: str, websocket: ProgressSink, db: Session, auth_context: dict | None = None):
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    parsed_target = urlparse(target_url)
    domain = parsed_target.netloc

    scan_record = models.Scan(domain_target=target_url, status="RUNNING", scan_type="crawler")
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    await websocket.send_text(f"[+] INITIATING DAST ENGINE ON: {target_url}")
    act_mod = {m.strip() for m in modules.split(",") if m.strip()}
    if not act_mod:
        act_mod = {"all"}
    await websocket.send_text(f"[i] Active Modules: {modules}")
    
    vulns_found_ref = [0]
    
    if ("tls" in act_mod or "all" in act_mod) and target_url.startswith("https"):
        await audit_ssl(target_url, scan_record, websocket, db)
        
    if "brute" in act_mod or "all" in act_mod:
        await fuzz_paths(target_url, domain, scan_record.id, websocket, db, vulns_found_ref)

    if "sqlmap" in act_mod or "all" in act_mod:
        await run_sqlmap_module(target_url, scan_record.id, websocket, db, vulns_found_ref)

    if "nuclei" in act_mod or "all" in act_mod:
        await run_nuclei_module(target_url, scan_record.id, websocket, db, vulns_found_ref)

    if "api_security" in act_mod or "all" in act_mod:
        await run_api_security_module(target_url, scan_record.id, websocket, db, vulns_found_ref)

    if "auth_scan" in act_mod or "all" in act_mod:
        await run_authenticated_scan_module(target_url, scan_record.id, websocket, db, vulns_found_ref, auth_context)
    
    visited = set()
    to_visit = [target_url]
    max_pages = 10
    links_discovered = 0

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
            
        visited.add(current_url)
        await websocket.send_text(f"[*] Scanning DOM: {current_url} ...")
        
        try:
            response = await asyncio.to_thread(requests.get, current_url, timeout=5)
            status_code = response.status_code
            
            db_link = models.DiscoveredLink(
                scan_id=scan_record.id,
                url=current_url,
                status_code=status_code,
                content_type=response.headers.get("Content-Type", "Unknown")
            )
            db.add(db_link)
            db.commit()
            db.refresh(db_link)
            links_discovered += 1

            if "headers" in act_mod or "all" in act_mod:
                messages = []
                audit_headers_and_fingerprint(response, current_url, db_link.id, scan_record.id, websocket, db, vulns_found_ref, messages)
                for m in messages:
                    await websocket.send_text(m)

            if "cors" in act_mod or "all" in act_mod:
                await test_cors(current_url, db_link.id, scan_record.id, websocket, db, vulns_found_ref)

            if "text/html" in db_link.content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                forms = soup.find_all("form")
                for form in forms:
                    password_inputs = form.find_all("input", type="password")
                    if password_inputs and not current_url.startswith("https"):
                        vulns_found_ref[0] += 1
                        finding = models.Finding(
                            scan_id=scan_record.id, link_id=db_link.id, severity="high",
                            finding_type="INSECURE_LOGIN", description="Password prompt served over unencrypted HTTP",
                            cvss_score="7.4", poc_payload=f"URL: {current_url}\nProtocol: HTTP"
                        )
                        db.add(finding)
                        await websocket.send_text(f"    [!] VULNERABILITY DETECTED: Insecure login form")
                        
                await active_fuzz_forms(soup, current_url, db_link.id, scan_record.id, websocket, db, vulns_found_ref, act_mod)

                if "playwright" in act_mod or "all" in act_mod:
                    await inspect_playwright_surface(soup, current_url, db_link.id, scan_record.id, websocket, db, vulns_found_ref)

                if "js_secret" in act_mod or "all" in act_mod:
                    await inspect_js_secrets(soup, current_url, db_link.id, scan_record.id, websocket, db, vulns_found_ref)

                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    full_url = urljoin(current_url, href)
                    
                    if urlparse(full_url).netloc == domain and full_url not in visited:
                        to_visit.append(full_url)
                        await websocket.send_text(f"    [+] Discovered Link (Added to queue): {href}")
            
        except Exception as e:
            await websocket.send_text(f"    [-] Request Error: {str(e)}")

    scan_record.status = "COMPLETED"
    db.commit()

    await websocket.send_text(f"")
    await websocket.send_text(f"[+] DAST ENGINE RUN #ID:{scan_record.id} COMPLETED.")
    await websocket.send_text(f"- Total Links Scanned: {links_discovered}")
    await websocket.send_text(f"- Issues Detected: {vulns_found_ref[0]}")
    await websocket.close()
