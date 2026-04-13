import asyncio
import requests
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fastapi import WebSocket
from sqlalchemy.orm import Session
from . import models

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

async def audit_ssl(target_url: str, scan_record: models.Scan, websocket: WebSocket, db: Session):
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


async def perform_crawl(target_url: str, modules: str, websocket: WebSocket, db: Session):
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    parsed_target = urlparse(target_url)
    domain = parsed_target.netloc

    scan_record = models.Scan(domain_target=target_url, status="RUNNING", scan_type="crawler")
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    await websocket.send_text(f"[+] INITIATING DAST ENGINE ON: {target_url}")
    act_mod = modules.split(",")
    await websocket.send_text(f"[i] Active Modules: {modules}")
    
    vulns_found_ref = [0]
    
    if ("tls" in act_mod or "all" in act_mod) and target_url.startswith("https"):
        await audit_ssl(target_url, scan_record, websocket, db)
        
    if "brute" in act_mod or "all" in act_mod:
        await fuzz_paths(target_url, domain, scan_record.id, websocket, db, vulns_found_ref)
    
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
