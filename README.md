# CAPE — Continuous Assurance Pentest Engine

**An evidence-oriented cybersecurity assessment framework for authorized security testing.**

CAPE brings security scanning, finding analysis, assessment planning, bounded attack checks, evidence collection, reporting, and auditability into one command-line workflow.

> **Authorization notice:** Use CAPE only against systems you own or are explicitly authorized to assess. The six bounded attack checks described below enforce a localhost/private-IP lab scope. That technical restriction is a safeguard, not proof of authorization.

## Overview

CAPE is a CLI-first framework designed primarily for Kali Linux and other Python 3.11+ environments. It orchestrates security tools and organizes assessment results through a shared workspace and normalized finding model.

```text
SCAN → SHOW → EXPLAIN → PLAN → ATTACK → DIFF → REPORT
          │                          │
          └── compliance mapping     └── audit-chain verification
```

The installed command is **`cape`** (as declared by the project's `pyproject.toml`).

## Key capabilities

- **Security scanning:** Run configured scanner plugins and collect results into CAPE's finding model.
- **Normalized findings:** Represent assessment results using a shared `Finding` schema.
- **Rule-based analysis:** Identify and prioritize opportunities using deterministic rules; the core opportunity identification is not an AI/ML decision engine.
- **Explainability:** Use `cape explain` to inspect the rules and scoring factors associated with an opportunity.
- **Compliance mapping:** Associate findings with available PCI DSS, SOC 2, and ISO/IEC 27001 control references.
- **Drift detection:** Use `cape diff` to compare assessment results and identify NEW, FIXED, REGRESSED, PERSISTENT, and IMPROVED findings.
- **Tamper-evident audit trail:** Record hash-chained audit events and verify the chain with `cape audit --verify`.
- **Assessment planning:** Build structured plans from identified opportunities.
- **Bounded attack checks:** Provide six limited, non-destructive checks for local/private lab targets (details below).
- **Guided legacy workflows:** Retain CMS, API, and Network workflows as guided-only entries; they are not represented as executable attack checks.
- **Reporting:** Generate JSON, HTML, and PDF reports with CISO, auditor, engineer, and combined audience options where supported by the report command.
- **Client organization:** Provide client-oriented workspace and report commands through `cape clients`.
- **Interactive operation:** Launch the guided menu by running `cape` without a subcommand, or use `cape menu`.

## Quick start

### Install

```bash
python -m pip install -r requirements.txt
```

For the full setup, including system packages and optional tools, see [INSTALL.md](INSTALL.md).

### Check the installation

```bash
cape doctor
```

### Example assessment workflow

Use an authorized lab target. For a local web application listening on port 3000:

```bash
cape scan web http://127.0.0.1:3000
cape show http://127.0.0.1:3000
cape plan http://127.0.0.1:3000
cape attack http://127.0.0.1:3000 --list
```

The attack modules are presented only when CAPE identifies a matching opportunity. The operator must review the proposed check and explicitly type `RUN` before a bounded module executes.

Other workflow commands include:

```bash
# Explain an opportunity
cape explain http://127.0.0.1:3000 --all

# Compare recent assessments
cape diff http://127.0.0.1:3000 --last 2

# Verify the audit chain
cape audit --verify

# Generate reports for different audiences
cape report http://127.0.0.1:3000 --audience ciso --format pdf
cape report http://127.0.0.1:3000 --audience auditor --format html
cape report http://127.0.0.1:3000 --audience engineer --format json
```

Check `cape <command> --help` for the options available in the installed version.

## Bounded lab attack checks

The following six modules are implemented in the updated attack build and are available through the interactive `cape attack` workflow when a matching opportunity is identified.

| Module | Implemented behaviour | Scope / limitation |
|---|---|---|
| `SQLiModule` | Uses SQLMap in detection-only mode when available; otherwise performs a read-only quote/error-indicator probe | An error indicator is a candidate signal, not proof of exploitable SQL injection. SQLMap's external-tool path requires separate lab verification. |
| `XSSModule` | Sends a harmless unique marker and checks whether the response reflects it | Reflection does not prove JavaScript execution; browser-based verification is not included. |
| `DirectoryEnumerationModule` | Uses Gobuster when available; otherwise checks a built-in list of 16 common paths sequentially | Enumeration is deliberately limited and low-concurrency. |
| `AuthModule` | Makes exactly one operator-supplied HTTP Basic authentication attempt | No password guessing, brute force, password spraying, or SSH authentication testing. |
| `SMBModule` | Uses Nmap SMB security/signing and share-enumeration scripts | Requires Nmap and a suitable private SMB lab host; external-tool execution was not verified in the build environment. |
| `HTTPHeadersModule` | Checks HTTP response headers for common security-header omissions or weak configurations | A configuration assessment only; it does not exploit the application. |

### Safety boundaries

The six bounded modules:

- Accept `localhost` or a single literal private IP address only.
- Reject public IP addresses, DNS hostnames, CIDR ranges, and URLs that point to a different host from the approved CAPE target.
- Pin HTTP connections to the validated IP and do not follow redirects.
- Require the operator to type `RUN` before executing a check.
- Avoid database extraction, remote file modification, unrestricted credential guessing, and post-exploitation actions.

Optional external tools used by some module paths include SQLMap, Gobuster, and Nmap. On Kali/Debian-based systems, these can be installed with the system package manager, for example:

```bash
sudo apt update
sudo apt install sqlmap gobuster nmap
```

The Python fallback checks for basic SQL-error indicators and bounded path enumeration do not require SQLMap or Gobuster. SMB enumeration requires Nmap. Authentication and HTTP-header checks use Python's standard library.

### Verification status and limitations

The build's `ATTACK_MODULE_STATUS.md` records the following verification results:

- Baseline test suite before the bounded attack changes: **126 passed**.
- Full test suite after the changes: **141 passed**.
- Python compile/import check: **passed**.
- Local HTTP-fixture tests cover the Python fallback paths for SQLi, XSS, directory enumeration, authentication, and HTTP headers.
- The SQLMap and Gobuster external-tool paths were not run in the build environment because those binaries were unavailable.
- SMB execution was not run because Nmap was unavailable.
- No external DVWA, OWASP Juice Shop, or Metasploitable VM was available during that build verification.

These are recorded build-time results, not a claim that every external-tool path has been tested on your machine. See [ATTACK_MODULE_STATUS.md](ATTACK_MODULE_STATUS.md) for the detailed module-by-module status and remaining verification work.

### Guided-only workflows

`CMSModule`, `APIModule`, and `NetworkModule` remain registered for continuity, but their legacy steps are labelled `GUIDED_ONLY_NOT_EXECUTED`. They must not be described as executable attack modules. Other historical placeholder modules are not part of the six bounded executable checks listed above.

## Main workflow and assurance capabilities

| Area | Command | Purpose |
|---|---|---|
| Scanning | `cape scan` | Run configured security scans against authorized targets. |
| Finding review | `cape show` | Display identified findings and opportunities. |
| Explainability | `cape explain` | Inspect why an opportunity received its score. |
| Planning | `cape plan` | Generate an assessment plan from identified opportunities. |
| Bounded checks | `cape attack` | Start an interactive attack-assessment session. |
| Drift | `cape diff` | Compare assessments and classify finding changes. |
| Audit | `cape audit` | Inspect audit events and verify the hash chain. |
| Reporting | `cape report` | Generate reports for the selected audience and format. |
| Client management | `cape clients` | Manage client-oriented workspaces and related reports. |
| Diagnostics | `cape doctor` | Check system health and dependencies. |

## Architecture

```text
CAPE/
├── cape/
│   ├── attack/       # Interactive attack engine and assessment modules
│   ├── cli/          # CLI entry point, menu, and command handlers
│   ├── core/         # Configuration, workspace, validation, and auditing
│   ├── db/           # Database models and migrations
│   ├── demo/         # Demonstration workflow
│   ├── plan/         # Assessment planning and workflow definitions
│   ├── reports/      # JSON, HTML, and PDF report generation
│   ├── scan/         # Scanning engine and security-tool plugins
│   ├── shared/       # Common models, enums, and utilities
│   └── show/         # Finding analysis, explainability, and remediation
├── examples/         # Example configurations
├── tests/            # Unit, integration, and regression tests
├── CAPE_data_datasets/ # Project datasets
├── README.md
├── INSTALL.md
├── ATTACK_MODULE_STATUS.md
├── SECURITY.md
├── requirements.txt
├── pyproject.toml
└── alembic.ini
```

## Scan profiles

The project includes scan profiles such as the following. Available tools and results depend on the local configuration and installed dependencies.

| Profile | Intended focus |
|---|---|
| `quick` | Faster initial port scan and web fingerprinting. |
| `recon` | Broader port and service enumeration. |
| `web` | Web-focused assessment using configured web tools. |
| `cms` | CMS discovery and configured CMS checks. |
| `network` | Network assessment and configured network checks. |
| `smb` | SMB enumeration and security checks. |
| `api` | API discovery and configured API checks. |
| `vuln` | Vulnerability-oriented scanner checks. |
| `full` | A broader sequence of configured assessment profiles. |

## CLI reference

The following shows the principal command families. Exact options can vary by command; use the built-in help for the installed version.

```text
cape scan <profile> <target> [options]
cape show <target> [options]
cape explain <target> [options]
cape plan <target> [options]
cape attack <target> [--module NAME] [--list]
cape diff <target> [options]
cape audit [options]
cape clients list
cape clients create <client_id> [--name NAME] [--contact EMAIL]
cape clients use <client_id>
cape clients report <client_id> [options]
cape clients audit <client_id> [options]
cape doctor [--fix]
cape report <target> [options]
cape menu
```

## Report audiences

| Audience | Intended contents |
|---|---|
| `ciso` | Executive summary, key risks, remediation progress, and compliance posture. |
| `auditor` | Audit-chain information, compliance control mapping, and drift summary. |
| `engineer` | Technical findings, evidence, explainability references, and remediation guidance. |
| `full` | Combined content for the available report audiences. |

Supported report formats include JSON, HTML, and PDF, subject to the installed dependencies and report configuration.

## Installation and security

- Installation details: [INSTALL.md](INSTALL.md)
- Security boundaries and responsible-use guidance: [SECURITY.md](SECURITY.md)
- Attack module implementation and verification details: [ATTACK_MODULE_STATUS.md](ATTACK_MODULE_STATUS.md)

## License

No open-source license has been applied to this project at present. All rights are reserved by the project author. Please contact the author for permission before copying, modifying, or redistributing this software.