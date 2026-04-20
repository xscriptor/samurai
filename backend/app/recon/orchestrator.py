from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Tuple

import asyncio

from ..progress import ProgressSink
from .logger import ReconStreamLogger
from .modules import (
    run_api_discovery,
    run_dns_enumerator,
    run_security_headers,
    run_subdomain_enumerator,
    run_technology_stack,
)


ModuleRunner = Callable[[str, Any], Any]


AVAILABLE_MODULES: Dict[str, Tuple[str, ModuleRunner]] = {
    "dns": ("[phase 1/5] dns enumeration", run_dns_enumerator),
    "subdomains": ("[phase 2/5] subdomain enumeration", run_subdomain_enumerator),
    "apis": ("[phase 3/5] api discovery", run_api_discovery),
    "headers": ("[phase 4/5] security headers", run_security_headers),
    "tech": ("[phase 5/5] technology stack", run_technology_stack),
}


def _expand_modules(recon_types: List[str]) -> List[str]:
    if not recon_types or "all" in recon_types:
        return list(AVAILABLE_MODULES.keys())

    ordered = []
    for key in AVAILABLE_MODULES.keys():
        if key in recon_types:
            ordered.append(key)
    return ordered



async def perform_web_recon(
    target: str,
    recon_types: List[str],
    websocket: ProgressSink,
    timeout_seconds: int = 300,
) -> Dict[str, Any]:
    logger = ReconStreamLogger(websocket)
    selected_modules = _expand_modules(recon_types)
    all_results: Dict[str, Any] = {}

    await logger.banner(target)
    await logger.line(f"[config] timeout={timeout_seconds}s modules={','.join(selected_modules)}")

    # Calculate timeout per module
    module_timeout = max(30, timeout_seconds // max(len(selected_modules), 1))
    
    for module_key in selected_modules:
        phase_title, runner = AVAILABLE_MODULES[module_key]
        await logger.phase(phase_title)
        try:
            # Run with individual timeout
            result = await asyncio.wait_for(
                runner(target, logger.line),
                timeout=module_timeout
            )
            all_results[module_key if module_key != "tech" else "technology"] = result
            await logger.line(f"[done] {module_key}")
        except asyncio.TimeoutError:
            await logger.line(f"[timeout] {module_key} exceeded {module_timeout}s")
        except Exception as exc:
            await logger.line(f"[error] {module_key}: {str(exc)[:120]}")

    await logger.phase("[summary]")
    await logger.line(f"modules executed={','.join(selected_modules)}")
    await logger.line(f"sections collected={len(all_results)}")
    await logger.line("status=complete")

    await websocket.send_json(
        {
            "type": "RECON_COMPLETE",
            "target": target,
            "results": all_results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

    return all_results
