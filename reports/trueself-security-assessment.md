# Web Application Vulnerability & Risk Assessment Report

> **Related:** See [Open Findings — Stored XSS & Broken Access Control](./trueself-findings-stored-xss-broken-access-control.md) for specific, currently unremediated vulnerabilities identified during this assessment.

**Target System:** `trueselfgiveback.com`  
**Assessment Type:** Grey-Box Web Application & Hardening Audit  
**Framework Alignment:** OWASP Top 10 (2021) / NIST SP 800-53 Rev. 5  
**Assessment Date:** October 2026  
**Assessor:** Egan Naik (Security Researcher)  

---

## 1. Executive Summary

A grey-box security assessment was conducted against `trueselfgiveback.com` to evaluate the web application's defense-in-depth posture, server HTTP response headers, session hygiene, and incoming threat telemetry. Initial automated and manual testing revealed baseline security header deficiencies and edge-network proxy resolution gaps, yielding an initial internal security score of **20/100**. Following structured remediation and hardening directives, security controls were applied and validated using intercepting proxy tooling.

---

## 2. Assessment Scope & Methodology

### Scope
* **Primary Target:** `https://trueselfgiveback.com`
* **In-Scope Components:** HTTP Response Headers, SSL/TLS Configurations, Client IP Resolution Logic, and Authentication Session Handling.

### Tooling & Approach
* **Intercepting Proxy:** Burp Suite Community Edition (HTTP History, Interceptor, Repeater).
* **Browsing Environment:** Firefox ESR configured with FoxyProxy and custom CA certificates.
* **Server Infrastructure:** LiteSpeed/Apache web server managed via DirectAdmin.

---

## 3. Findings & Risk Summary

| Finding ID | Vulnerability / Deficiency Description | Risk Severity | CVSS v3.1 Score | Status |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Missing HTTP Security Hardening Headers | Medium | 5.3 | **Remediated** |
| **SEC-02** | Unrestricted Script Execution (Missing CSP) | High | 7.2 | **Mitigated (Report-Only)** |
| **SEC-03** | Internal Gateway / Reverse Proxy IP Logging Flaw | Low | 3.1 | **Remediated** |

---

## 4. Vulnerability Breakdown & Remediation

### SEC-01: Missing HTTP Security Hardening Headers
* **Description:** The application failed to enforce HTTP response headers required to protect users against Clickjacking, MIME-type sniffing, and unencrypted downgrade attacks.
* **Missing Directives:** `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.
* **Remediation Applied:** Injected Apache/LiteSpeed directives via `.htaccess`:
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "DENY"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=()"
