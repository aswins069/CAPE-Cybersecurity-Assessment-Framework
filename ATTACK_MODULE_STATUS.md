# CAPE V2 — Attack Module Implementation and Verification Status

This document records the implementation state of the bounded attack checks added to this build.

## Verification performed

- Baseline test suite before changes: **126 passed**.
- Full test suite after changes: **141 passed**.
- Python compile/import check: **passed**.
- New local-only integration tests use an in-process HTTP server bound to `127.0.0.1`.
- No external lab VM (DVWA, Juice Shop, or Metasploitable) was available during this build.
- External binaries `sqlmap`, `gobuster`, `nmap`, `smbclient`, and `hydra` were not installed in the build environment.

## Six bounded modules

| Module | Implementation | Verified in this environment | Accurate claim |
|---|---|---|---|
| SQLi | SQLMap detection-only path when installed; otherwise a read-only quote/error-indicator probe | Python fallback tested against a local HTTP fixture; SQLMap path not run because SQLMap is absent | Performs a basic SQL-error-indicator probe; SQLMap integration is implemented but needs a lab run |
| XSS | Sends a harmless unique marker and checks reflection | Tested against a local HTTP fixture | Detects reflected input candidates; does not verify JavaScript execution |
| Directory enumeration | Gobuster path when installed; otherwise sequentially checks 16 common paths | Python fallback tested against a local HTTP fixture; Gobuster path not run because Gobuster is absent | Performs bounded directory/path enumeration |
| Authentication | Exactly one operator-supplied HTTP Basic authentication attempt | Tested against a local HTTP fixture; secret not written to evidence | Tests one HTTP Basic credential pair; no brute force, password spraying, or SSH testing |
| SMB | Nmap SMB signing/security/share-enumeration safe-script check | Not run because Nmap is absent | Implementation is present; requires Nmap and a private SMB lab host for verification |
| HTTP headers | Checks common HTTP security response headers | Tested against a local HTTP fixture | Performs HTTP security-header assessment |

## Safety boundaries

- New bounded modules accept `localhost` or a single literal private IP address only.
- Public IPs, DNS hostnames, CIDR ranges, and cross-host URLs are rejected.
- HTTP probes pin connections to the validated IP and do not follow redirects.
- SQLMap is configured for low-risk detection only; database enumeration and data extraction are not requested.
- XSS uses a harmless marker; reflection is not reported as confirmed executable XSS.
- Authentication testing makes one supplied HTTP Basic attempt only.
- Directory enumeration uses a short built-in list and low concurrency.
- SMB testing is limited to read-oriented Nmap scripts.
- Every new module requires the operator to type `RUN`.

These restrictions are guardrails, not proof of authorization. Only assess systems for which explicit permission exists.

## Existing CAPE functionality

- Existing SCAN, SHOW, PLAN, reporting, plugin, explainability, compliance, drift, and audit code was not intentionally redesigned.
- The attack engine now passes the existing scan findings to attack modules (instead of passing an empty list), checks module tool availability, records step evidence, and appends an audit event for each attempted step.
- Legacy CMS, API, and Network workflows remain registered. Their placeholder execution functions now explicitly return `GUIDED_ONLY_NOT_EXECUTED` instead of pretending that an action succeeded.
- The four assurance-pillar implementations were not rewritten.

## Remaining verification work

1. Install SQLMap, Gobuster, and Nmap on the intended Kali/Linux host.
2. Run SQLi and directory enumeration against a local DVWA/Juice Shop lab.
3. Run SMB enumeration against a local Metasploitable/Windows lab with SMB enabled.
4. Validate the resulting evidence and audit-chain entries in the actual CAPE installation.
5. Do not claim the SQLMap or SMB external-tool paths were verified until those lab runs have been completed.
