# Security Policy & Responsible Use — CAPE

## ⚠️ IMPORTANT LEGAL NOTICE

**CAPE is designed exclusively for AUTHORIZED security assessments.**

Unauthorized use of this tool against systems you do not own or do not have explicit written permission to test is **illegal** in most jurisdictions, including but not limited to:

- Computer Fraud and Abuse Act (CFAA) — United States
- Computer Misuse Act 1990 — United Kingdom
- Cybercrime Convention — Council of Europe
- Similar laws in virtually all countries

**Violations can result in criminal prosecution, civil liability, and imprisonment.**

The six bounded modules added for SQLi indicators, reflected-input probes,
directory enumeration, single-attempt HTTP Basic checks, SMB enumeration,
and HTTP security-header assessment enforce a technical restriction to
localhost or one literal private IP address and require an explicit `RUN`
confirmation. They reject public IPs, DNS hostnames, CIDR ranges, and
cross-host test URLs. HTTP probes pin the connection to the validated IP
and do not follow redirects.

This technical restriction is not proof of authorization. It does not
replace written permission, and legacy scan/guided workflows do not all
share the same target-scope enforcement. Only use CAPE against systems
you own or a lab environment you control (e.g. a local VM, DVWA,
OWASP Juice Shop, Metasploitable, or an authorized CTF range).

## Audit Logging

Every action is still logged to `~/.cape/logs/audit.log`:
- Every tool execution (exact command line)
- Every scan start and completion
- Every attack session event

**Do not delete or modify audit logs.**

## Appropriate Use Cases

✅ Your own systems and lab VMs
✅ Deliberately vulnerable practice targets (Metasploitable, DVWA, etc.)
✅ CTF (Capture The Flag) competitions
✅ Coursework/demo environments you control

## Inappropriate Use Cases

❌ Scanning or attacking systems you don't own or control
❌ Any target outside a lab/classroom/CTF context

## Vulnerability Disclosure

If you discover a security vulnerability in CAPE itself, please disclose responsibly:

1. Do NOT create a public GitHub issue
2. Email the maintainers with details
3. Allow 90 days for a fix before public disclosure
