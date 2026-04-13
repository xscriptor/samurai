# Dynamic Application Security Testing (DAST) Engine

This document details the capabilities and methodologies employed by the DAST Scanner module within the XWA-SEC platform. 

The DAST module represents an active, "black-box" testing approach. Unlike static analysis, which examines source code at rest, DAST interacts with the running web application from the outside, exactly as an attacker would. It probes the application's attack surface in real-time, executing non-destructive exploits and analyzing HTTP responses to identify security flaws.

## Core Capabilities

### 1. Cryptographic Validation (TLS/SSL)
Before interacting with the HTTP layer, the engine establishes a direct socket connection to evaluate the transport layer security (TLS/SSL). It identifies the negotiated protocol version and cipher suite, explicitly flagging servers that still support obsolete and compromised protocols such as SSLv3, TLSv1.0, or TLSv1.1.

### 2. HTTP Header Auditing and Fingerprinting
The engine passively inspects server responses to identify the underlying technology stack (e.g., retrieving `Server` and `X-Powered-By` headers). It also verifies the presence and correct configuration of critical security headers:
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Content-Type-Options`
- `Set-Cookie` flags (`HttpOnly`, `Secure`, `SameSite`)

### 3. Exposed Surface Mapping (Blind Routing)
To uncover unprotected sensitive files that are not linked within the application's HTML, the engine performs targeted brute-force requests against common configuration paths. These include version control metadata (`/.git/config`), environment files (`/.env`), and dependency lists (`/requirements.txt`). Bypassing standard navigation often reveals critical infrastructure misconfigurations.

### 4. Active Parameter Fuzzing
During the initial DOM traversal, the engine intercepts all HTML forms (`<form>`) and their respective input fields. It systematically injects malicious payloads into these parameters:
- **SQL Injection (SQLi):** Payloads such as `' OR 1=1--` are injected to provoke unhandled database exceptions resulting in HTTP 500 errors or syntax leakages.
- **Cross-Site Scripting (XSS):** Payloads such as `<script>alert(1)</script>` are injected to determine if the server reflects the input unmodified into the HTML response, confirming a Reflected XSS vulnerability.

## Common Vulnerability Scoring System (CVSS)
Each identified vulnerability is mapped to an estimated CVSS score and severity level based on the nature of the flaw. For example, a confirmed Reflected XSS typically yields a High severity score (e.g., 6.1), whereas a syntax-breaking SQL Injection anomaly yields a Critical score (e.g., 9.8).

## Proof of Concept Generation
For every active vulnerability found, the engine logs the exact HTTP method, URL, and payload data required to reproduce the exploit. This Proof of Concept (PoC) trace allows security auditors to manually verify and remediate the issue without ambiguity.
