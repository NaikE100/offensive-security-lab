# Web Application Penetration Testing Methodology

This document outlines the systematic testing process used during manual web application security assessments. The methodology aligns with the **OWASP Top 10 (2021)** and **OWASP Web Security Testing Guide (WSTG v4.2)**.

---

## Phase 1: Reconnaissance & Infrastructure Fingerprinting
* [ ] **Tech Stack Identification:** Inspect HTTP headers (`Server`, `X-Powered-By`), cookies, and file extensions using Burp Suite or `Wappalyzer`.
* [ ] **Subdomain & Endpoint Discovery:** Enumerate hidden paths, staging endpoints, and backup files (`/api`, `/admin`, `.env`, `.git`).
* [ ] **SSL/TLS & Transport Audit:** Validate certificate validity, HTTPS enforcement, and HSTS header implementation.

---

## Phase 2: Configuration & Deploy Management
* [ ] **Security Header Verification:** Check for active protection headers:
  * `Strict-Transport-Security`
  * `Content-Security-Policy`
  * `X-Frame-Options`
  * `X-Content-Type-Options`
* [ ] **Information Disclosure:** Scan raw response bodies and JS bundles for exposed API keys, internal IP addresses, or environment variables.

---

## Phase 3: Identity & Session Management
* [ ] **Cookie Security Flags:** Ensure all authentication cookies enforce `HttpOnly`, `Secure`, and `SameSite=Lax/Strict`.
* [ ] **Session Termination:** Verify token invalidation on explicit logout or server-side password updates.
* [ ] **Brute-Force Resistance:** Test login and API endpoints for rate-limiting enforcement.

---

## Phase 4: Access Control & Business Logic (Authorization)
* [ ] **Insecure Direct Object References (IDOR):** Modify object identifiers (e.g., `GET /api/user?id=101` $\rightarrow$ `id=102`) in Burp Repeater to attempt unauthorized data access.
* [ ] **Privilege Escalation:** Attempt vertical access control bypass (Standard User accessing Admin endpoints).
* [ ] **Database Row-Level Security (RLS):** For Supabase/Postgres platforms, verify that query policies enforce tenant-level isolation.

---

## Phase 5: Input Validation & Injection Flaws
* [ ] **Cross-Site Scripting (XSS):** Test input fields and query parameters for reflected and stored payload execution.
* [ ] **SQL Injection (SQLi):** Test forms and API parameters with special characters (`'`, `"`, `OR 1=1`) to identify unhandled database exceptions.
* [ ] **Parameter Tampering:** Intercept POST payloads using Burp Intercept to alter values, roles, or prices before server submission.

---

## Phase 6: Reporting & Risk Scoring
* [ ] Assign **CVSS v3.1** base metrics to all validated vulnerabilities.
* [ ] Draft reproducible **Proof-of-Concept (PoC)** steps and raw HTTP requests/responses.
* [ ] Provide actionable, code-level remediation steps for engineering teams.
