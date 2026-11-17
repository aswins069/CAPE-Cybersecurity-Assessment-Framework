"""CAPE Demo Mode (spec Section 27).

Runs the full CAPE pipeline — scan-shaped data -> findings -> show ->
explainability -> compliance -> audit -> report — using bundled sample
scanner output instead of live tools, so the pipeline can be
demonstrated without nmap/nikto/whatweb/etc. installed.

All records created by demo mode are explicitly tagged as demo data
(tags include "demo_data", extra["demo"] is True, and the target is
prefixed "demo-") per Section 28: CAPE must never claim a scanner ran
when it did not, and demo data must be clearly labeled as such.
"""
