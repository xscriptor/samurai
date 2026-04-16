# Samurai Development Roadmap

This document tracks the strategic steps required to evolve the Samurai application into a full-scale web cybersecurity suite. 
This file is formatted to be synced automatically with GitHub Issues using the `xgh` roadmap standard.

## Infrastructure & Core Initialization <!-- phase:infrastructure -->

- [x] Dockerize frontend (Angular) and backend (FastAPI) environments (#1)
- [x] Integrate PostgreSQL and Redis architectures for persistence (#2)
- [x] Implement the Nothing Design System UI tokens and layout (#3)
- [x] Configure Docker-compose for rapid local development (HMR Support) (#4)

## Real-time Scanning Engine <!-- phase:real-time-engine -->

- [x] Scaffold SQLAlchemy models for Scans and Findings (#5)
- [x] Create WebSocket endpoints for real-time console streaming (#6)
- [x] Integrate native Nmap execution as an asynchronous Python subprocess (#7)
- [x] Build the "Nothing Terminal" component in Angular to render WebSocket streams (#8)

## Deep Vulnerability Analysis Integration <!-- phase:vuln-analysis -->

- [x] Integrate SQLMap subprocess runner for automated SQL Injection vulnerability checks (#9)
- [x] Connect Nuclei vulnerability scanner templates to expand the footprint engine (#10)
- [/] Implement robust `stdout` parsing heuristics for automated Finding severity classification (#11)
- [/] Establish asynchronous fuzzing for directory and file brute-forcing (#12)

## Headless Reconnaissance & Crawling <!-- phase:recon-crawler -->

- [/] Add headless browser nodes (Playwright) to execute JavaScript-heavy reconnaissance (#13)
- [/] Intercept, capture, and analyze XHR/Fetch network requests dynamically (#14)
- [x] Implement visual screenshot capture module for successfully resolved domains (#15)
- [x] Automate Site Topology mapping through recursive spider crawling (#16)

## Security, Auth & Production Hardening <!-- phase:production-hardening -->

- [/] Wrap FastAPI backend routes with JWT Authentication middleware (#17)
- [/] Add RBAC (Role-Based Access Control) to restrict scan actions by user level (#18)
- [/] Implement Redis-based rate limiting to prevent application scan flooding (#19)
- [/] Setup scheduled recurrent scans via Celery Beat tasks (#20)
- [x] Develop exportable Executive Reports (PDF and CSV format) for compiled findings (#21)
