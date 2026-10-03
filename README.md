# Web Application Penetration Testing & AppSec Portfolio

Welcome to my security research and offensive security portfolio. With a strong background in full-stack web development (PHP, JavaScript, MySQL, PostgreSQL/Supabase) and Linux server administration, I specialize in **Web Application Penetration Testing**, **Vulnerability Assessment**, and **Defensive Telemetry Engineering**.

---

## 🛠️ Technical Skill Set

* **Offensive Security Testing:** Web App Pentesting, OWASP Top 10, Parameter Tampering, Authentication & Authorization Bypass, Logic Flaws, IDOR.
* **Testing Tooling:** Burp Suite Professional/Community, OWASP ZAP, FoxyProxy, curl, Nmap, Wfuzz/Gobuster.
* **Application Architecture:** PHP, Node.js/React, Supabase (RLS), MySQL, Apache/LiteSpeed, DirectAdmin.
* **Security & Hardening:** HTTP Hardening Headers (HSTS, CSP, Permissions-Policy), ModSecurity WAF, Email Security (SPF, DKIM, DMARC), Log Telemetry.

---

## 🚀 Featured Projects & Live Security Labs

### 1. Live Target Hardening & Security Operations Panel (`TrueSelf Platform`)
* **Overview:** Designed and built a custom **Security Dashboard & Threat Intelligence Ledger** embedded directly within a production web application.
* **Offensive & Defensive Controls:**
  * Configured HTTP Security Headers (`Strict-Transport-Security`, `X-Frame-Options`, `Content-Security-Policy`).
  * Engineered real-time client IP resolution and geolocation logging to capture anomalous traffic.
  * Implemented an automated database ledger for one-click IP blocking and perimeter defense.
* **Repository Link / Artifacts:** `tooling/threat-ledger-logger.php` | `reports/trueself-security-assessment.md`

### 2. Manual Web Application Vulnerability Assessments
* Executed systematic manual pentesting using **Burp Suite Proxy** against web endpoints to evaluate:
  * **Session Management:** Verification of `HttpOnly`, `Secure`, and `SameSite` flags on authentication cookies.
  * **Input Sanitization:** Testing form inputs and query parameters for Reflected/Stored XSS and SQL Injection vulnerabilities.
  * **Access Control:** Auditing Row-Level Security (RLS) policies and direct object references (IDOR).

---

## 📄 Security Reports & Artifacts

| Document | Category | Key Frameworks |
| :--- | :--- | :--- |
| [TrueSelf Web Assessment Report](./reports/trueself-security-assessment.md) | Web App Pentest / Audit | OWASP ASVS, NIST CSF |
| [Web Testing Methodology](./methodologies/web-app-testing-checklist.md) | Testing Standard | OWASP Top 10 (2021) |
| [TryHackMe Writeups & Labs](./reports/thm-room-writeups/) | Lab Challenges | Junior Pentester Path |
| [TrueSelf Findings — Stored XSS & Broken Access Control](https://github.com/NaikE100/offensive-security-lab/blob/main/reports/trueself-findings-stored-xss-broken-access-control.md) | Vulnerability Findings (Open) | OWASP Top 10 (2021) |

---

## 📈 Certifications & Learning Roadmap

* **In Progress:** TryHackMe *Junior Penetration Tester* Track
* **Target Credentials:** eJPT (eLearnSecurity Junior Penetration Tester) / CompTIA PenTest+
