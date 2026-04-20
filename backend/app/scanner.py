import asyncio
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from fastapi import WebSocket
from sqlalchemy.orm import Session
from . import models
from .progress import ProgressSink

PORT_OPEN_PATTERN = re.compile(r"^(\d+)\/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?$", re.IGNORECASE)

NMAP_PROFILES = {
    "quick": ["-F", "-sV", "-T3"],
    "balanced": ["-sV", "--top-ports", "1000", "-T3"],
    "deep": ["-sV", "-sC", "--top-ports", "2000", "-T4"],
    "udp": ["-sU", "--top-ports", "200", "-T3"],
}

EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_PATTERN = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}")
REFLECT_PROBE = "samurai_probe_93f52"

ACTIVE_NMAP_PROCESSES: dict[int, asyncio.subprocess.Process] = {}


def request_cancel_scan(scan_id: int, db: Session) -> bool:
    process = ACTIVE_NMAP_PROCESSES.get(scan_id)
    if not process:
        return False

    if process.returncode is None:
        process.terminate()

    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if scan and scan.status == "RUNNING":
        scan.status = "CANCELLED"
        db.commit()

    return True


def _ensure_web_target(target: str):
    normalized = target.strip()
    if normalized.startswith("http://") or normalized.startswith("https://"):
        return normalized
    return f"http://{normalized}"


def _same_domain(url: str, domain: str):
    return urlparse(url).netloc == domain


def _extract_contact_data(text: str):
    emails = sorted(set(EMAIL_PATTERN.findall(text)))
    phones = sorted(set(PHONE_PATTERN.findall(text)))
    phones = [p for p in phones if len(re.sub(r"\D", "", p)) >= 7]
    return emails[:20], phones[:20]


def _find_unsanitized_candidates(soup: BeautifulSoup):
    candidates = []

    for form in soup.find_all("form"):
        form_action = form.get("action", "")
        form_method = (form.get("method", "get") or "get").lower()
        names = []

        for inp in form.find_all("input"):
            input_type = (inp.get("type") or "text").lower()
            if input_type not in {"text", "search", "email", "url", "tel", "password"}:
                continue

            if inp.get("pattern") or inp.get("maxlength"):
                continue

            names.append(inp.get("name") or inp.get("id") or "unnamed_input")

        for textarea in form.find_all("textarea"):
            if textarea.get("maxlength"):
                continue
            names.append(textarea.get("name") or textarea.get("id") or "unnamed_textarea")

        if names:
            candidates.append({
                "action": form_action,
                "method": form_method,
                "fields": sorted(set(names))[:12]
            })

    return candidates[:8]


def _build_reflection_probe_url(current_url: str):
    parsed = urlparse(current_url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    if not query_items:
        return None

    first_key = query_items[0][0]
    probe_items = [(k, REFLECT_PROBE if k == first_key else v) for k, v in query_items]
    probe_query = urlencode(probe_items, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))


async def _run_web_surface_scan(
    base_target: str,
    scan_record: models.Scan,
    websocket: ProgressSink,
    db: Session,
    collect_contacts: bool,
    scan_unsanitized: bool,
    max_pages: int,
):
    await websocket.send_text("[*] WEB_APP_SURFACE module enabled. Crawling pages for app-layer exposure...")

    target_url = _ensure_web_target(base_target)
    domain = urlparse(target_url).netloc
    queue = [target_url]
    visited = set()
    effective_max_pages = max(1, min(max_pages, 40))
    contact_hits = 0
    unsanitized_hits = 0
    reflected_hits = 0

    while queue and len(visited) < effective_max_pages:
        current_url = queue.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            response = await asyncio.to_thread(requests.get, current_url, timeout=6)
        except Exception:
            continue

        db_link = models.DiscoveredLink(
            scan_id=scan_record.id,
            url=current_url,
            status_code=response.status_code,
            content_type=response.headers.get("Content-Type", "unknown")
        )
        db.add(db_link)
        db.commit()
        db.refresh(db_link)

        if "text/html" not in (db_link.content_type or ""):
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        if collect_contacts:
            emails, phones = _extract_contact_data(soup.get_text(" "))
            if emails or phones:
                lines = [f"URL: {current_url}"]
                if emails:
                    lines.append("Emails:")
                    lines.extend([f"- {item}" for item in emails[:10]])
                if phones:
                    lines.append("Phones:")
                    lines.extend([f"- {item}" for item in phones[:10]])

                finding = models.Finding(
                    scan_id=scan_record.id,
                    link_id=db_link.id,
                    severity="low",
                    finding_type="CONTACT_INFO_DISCLOSURE",
                    description="Contact data discovered in page content.",
                    cvss_score="2.3",
                    poc_payload="\n".join(lines)
                )
                db.add(finding)
                db.commit()
                contact_hits += 1
                await websocket.send_text(f"    [WEB_CONTACT] {current_url} emails={len(emails)} phones={len(phones)}")

        if scan_unsanitized:
            unsanitized_forms = _find_unsanitized_candidates(soup)
            if unsanitized_forms:
                for item in unsanitized_forms:
                    finding = models.Finding(
                        scan_id=scan_record.id,
                        link_id=db_link.id,
                        severity="medium",
                        finding_type="UNSANITIZED_INPUT_CANDIDATE",
                        description="Form fields without visible constraints (pattern/maxlength) may require sanitization review.",
                        cvss_score="4.2",
                        poc_payload=(
                            f"URL: {current_url}\n"
                            f"Method: {item['method'].upper()}\n"
                            f"Action: {item['action']}\n"
                            f"Fields: {', '.join(item['fields'])}"
                        )
                    )
                    db.add(finding)
                db.commit()
                unsanitized_hits += len(unsanitized_forms)
                await websocket.send_text(f"    [WEB_UNSANITIZED] {current_url} forms={len(unsanitized_forms)}")

            probe_url = _build_reflection_probe_url(current_url)
            if probe_url:
                try:
                    probe_res = await asyncio.to_thread(requests.get, probe_url, timeout=6)
                    if REFLECT_PROBE in (probe_res.text or ""):
                        finding = models.Finding(
                            scan_id=scan_record.id,
                            link_id=db_link.id,
                            severity="high",
                            finding_type="REFLECTED_INPUT_ECHO",
                            description="A query probe string was reflected in the response without normalization.",
                            cvss_score="6.1",
                            poc_payload=f"Probe URL: {probe_url}\nProbe: {REFLECT_PROBE}"
                        )
                        db.add(finding)
                        db.commit()
                        reflected_hits += 1
                        await websocket.send_text(f"    [WEB_UNSANITIZED] {current_url} reflected=true")
                except Exception:
                    pass

        for anchor in soup.find_all("a", href=True):
            href = anchor.get("href")
            full_url = urljoin(current_url, href)
            if _same_domain(full_url, domain) and full_url not in visited and full_url not in queue:
                queue.append(full_url)

    await websocket.send_text(f"[i] WEB_APP_SURFACE completed. pages_scanned={len(visited)}")
    await websocket.send_text(
        f"[SUMMARY] WEB CRAWL: pages={len(visited)} | contacts={contact_hits} | unsanitized={unsanitized_hits} | reflected={reflected_hits}"
    )

    return {
        "pages_scanned": len(visited),
        "contacts": contact_hits,
        "unsanitized": unsanitized_hits,
        "reflected": reflected_hits,
    }

async def perform_nmap_scan(
    target: str,
    websocket: ProgressSink,
    db: Session,
    profile: str = "quick",
    timeout_seconds: int = 180,
    web_scan: bool = False,
    collect_contacts: bool = False,
    scan_unsanitized: bool = False,
    max_pages: int = 10,
):
    """
    Ejecuta un escaneo de Nmap superficial (Top 100 ports y versiones) 
    y transmite el progreso crudo línea a línea vía WebSocket.
    """
    # 1. Crear el registro MOCK en BD
    # (Para no ralentizar el test con un worker asíncrono puro, inyectaremos directo)
    selected_profile = profile if profile in NMAP_PROFILES else "quick"
    selected_args = NMAP_PROFILES[selected_profile]
    effective_timeout = max(30, min(timeout_seconds, 900))

    scan_type = f"port_scan:{selected_profile}"
    if web_scan:
        scan_type += "+web"

    scan_record = models.Scan(domain_target=target, status="RUNNING", scan_type=scan_type)
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    await websocket.send_text(f"[SCAN_META] scan_id={scan_record.id}")
    await websocket.send_text(f"[+] Starting nmap scan on target: {target}")
    await websocket.send_text(f"[i] Profile: {selected_profile} | Timeout: {effective_timeout}s")
    
    # 2. Ejecutar nmap a nivel de OS
    try:
        process = await asyncio.create_subprocess_exec(
            "nmap", *selected_args, target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        ACTIVE_NMAP_PROCESSES[scan_record.id] = process
    except FileNotFoundError:
        scan_record.status = "ERROR"
        db.commit()
        await websocket.send_text("[!] Nmap binary not found in runtime environment.")
        await websocket.close()
        return

    # 3. Leer la salida estándar en vivo
    open_ports_found = {}
    timed_out = False
    loop = asyncio.get_running_loop()
    start_ts = loop.time()
    
    if process.stdout:
        while True:
            if loop.time() - start_ts > effective_timeout:
                timed_out = True
                await websocket.send_text(f"[!] Scan timeout reached ({effective_timeout}s). Stopping nmap process...")
                process.terminate()
                break

            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if not line:
                break
            text_line = line.decode('utf-8').rstrip()
            
            # Streaming crudo a la terminal Frontend
            await websocket.send_text(text_line)
            
            # Simple heurística para sacar info básica superficialmente como "hallazgo"
            match = PORT_OPEN_PATTERN.match(text_line.strip())
            if match:
                port = match.group(1)
                proto = match.group(2).lower()
                service = (match.group(3) or "unknown").strip()
                version = (match.group(4) or "").strip()
                open_ports_found[f"{port}/{proto}"] = {
                    "port": port,
                    "proto": proto,
                    "service": service,
                    "version": version,
                    "raw": text_line,
                }
                await websocket.send_text(f"[OPEN_PORT] {port}/{proto} {service} {version or 'n/a'}")

    try:
        await asyncio.wait_for(process.wait(), timeout=8)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
    finally:
        ACTIVE_NMAP_PROCESSES.pop(scan_record.id, None)
    
    # 4. Guardar resultados y marcar como finalizado
    if scan_record.status == "CANCELLED":
        pass
    elif timed_out:
        scan_record.status = "ERROR"
    else:
        scan_record.status = "COMPLETED" if process.returncode == 0 else "ERROR"
    
    for key in sorted(open_ports_found.keys()):
        parsed = open_ports_found[key]
        finding = models.Finding(
            scan_id=scan_record.id,
            severity="info",
            finding_type="OPEN_PORT",
            description=parsed["raw"],
            poc_payload=f"port={parsed['port']}\nprotocol={parsed['proto']}\nservice={parsed['service']}\nversion={parsed['version']}"
        )
        db.add(finding)

    db.commit()

    if open_ports_found:
        await websocket.send_text("[SUMMARY] OPEN PORTS DISCOVERED:")
        for key in sorted(open_ports_found.keys()):
            parsed = open_ports_found[key]
            await websocket.send_text(
                f"    - {parsed['port']}/{parsed['proto']} | {parsed['service']} | {parsed['version'] or 'n/a'}"
            )
    else:
        await websocket.send_text("[SUMMARY] NO OPEN PORTS FOUND.")

    if web_scan and scan_record.status == "COMPLETED":
        web_summary = await _run_web_surface_scan(
            target,
            scan_record,
            websocket,
            db,
            collect_contacts=collect_contacts,
            scan_unsanitized=scan_unsanitized,
            max_pages=max_pages,
        )
        await websocket.send_text(
            f"[SUMMARY] WEB REPORT READY: pages={web_summary['pages_scanned']} | contacts={web_summary['contacts']} | unsanitized={web_summary['unsanitized']} | reflected={web_summary['reflected']}"
        )

    status_label = "TIMEOUT" if timed_out else scan_record.status
    await websocket.send_text(f"[+] Scan #ID:{scan_record.id} {status_label}. ({len(open_ports_found)} open ports saved).")
    await websocket.close()
