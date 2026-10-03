# Vulnerability Assessment Findings — TrueSelf Platform (trueselfgiveback.com)

**Assessment type:** Manual grey-box testing (authorized, self-owned production target)
**Tester:** Egan Naik
**Date identified:** October 2026
**Status:** 🔴 Open — Not yet remediated (documented for tracking and transparency)

---

## Summary

During manual testing of the TrueSelf community story wall feature, two related vulnerabilities were identified in the story submission and rendering pipeline. Both are rated **High** severity due to the platform's user base, which includes vulnerable individuals and, on certain subdomains, minors.

| ID | Title | OWASP Category | Severity |
|----|-------|-----------------|----------|
| TS-001 | Broken Access Control on Story Submission Endpoint | A01:2021 – Broken Access Control | High |
| TS-002 | Stored Cross-Site Scripting (XSS) via Community Story Wall | A03:2021 – Injection | High |

These two findings compound one another: TS-001 provides an unauthenticated path to inject content, and TS-002 means that injected content executes in every visitor's browser.

---

## TS-001: Broken Access Control on Story Submission Endpoint

### Description

The client-side application (`index.html`) gates story submission behind a login check implemented entirely in JavaScript:

```javascript
async function handleBridgeTheGap(e) {
    if (e) e.preventDefault();
    if (!checkIsLoggedIn()) {
        openSigninModal();
        return;
    }
    // ... proceeds to POST to the API
}
```

`checkIsLoggedIn()` checks only for the presence of client-side state (`localStorage` keys, or the string "Sign Out" in the page body). This check runs in the browser and is never enforced by the server. The actual submission endpoints:

- `POST /api/submit_story.php`
- `POST https://facilitators.trueselfgiveback.com/api.php?action=create_post`

accept and process requests without verifying a valid server-side session (e.g., checking `$_SESSION` against the `PHPSESSID` cookie already issued elsewhere on the platform).

### Evidence

A content submission referencing an external backlink service (`bonusbacklinks.com`) was published to the live community wall under the display name "Cora Guerra," dated 8/27/2026. This submission was not made by a registered user through the normal sign-up flow, consistent with an automated bot calling the submission endpoint directly, bypassing the UI (and therefore the client-side login check) entirely.

### Impact

- Any party, authenticated or not, can publish arbitrary content to a public-facing community feature.
- This is the direct enabling condition for TS-002 (stored XSS): without a valid auth barrier, a malicious actor can submit XSS payloads as freely as the spam bot submitted advertising content.
- Reputational and safety risk: the platform serves individuals disclosing personal struggles, including minors on dedicated subdomains (`student.`, `teens.`). Unmoderated, unauthenticated posting creates a direct vector for abuse, harassment, or harmful content targeting this population.

### Steps to Reproduce

1. Identify the submission endpoint via browser DevTools Network tab while submitting a legitimate story.
2. Send a `POST` request directly to the endpoint (via `curl`, Postman, or a script) with a crafted JSON/form body, omitting any session cookie or using no prior authentication.
3. Observe the submission is accepted and rendered on the public story wall.

### Remediation (Recommended, Not Yet Implemented)

1. Enforce authentication server-side in `submit_story.php` / `api.php`: validate the PHP session before processing any submission; reject with HTTP 401 if absent or invalid.
2. Apply rate limiting (per-IP and per-account) to the submission endpoint independent of auth status.
3. Consider CAPTCHA or equivalent bot mitigation at account sign-up to reduce automated account creation as a secondary bypass path.
4. Add server-side logging/alerting on submissions from sessions that fail validation, to detect further bypass attempts.

---

## TS-002: Stored Cross-Site Scripting (XSS) via Community Story Wall

### Description

User-submitted fields returned by `GET /api/get_stories.php` — specifically `content_raw`, `display_name`, and `status_tag` — are inserted directly into the DOM via unescaped template literals assigned through `innerHTML`:

```javascript
container.innerHTML = stories.map(story => `
    <div class="story-polaroid-item" data-category="${normalizedTag}" ...>
        <span>${displayTag}</span>
        <p>"${story.content_raw}"</p>
        <p>— ${story.display_name || 'Anonymous'}</p>
    </div>
`).join('');
```

No HTML-escaping or sanitization is applied client-side before insertion, and there is no confirmed server-side sanitization at the point of storage either. Any HTML or JavaScript submitted as story content, a display name, or a status tag will be rendered and executed as live markup in the browser of every visitor who loads the community wall.

### Impact

- **Stored/persistent XSS**: unlike reflected XSS, a single malicious submission affects every subsequent visitor to the page, not just the submitter.
- Combined with TS-001, this is exploitable without any account or authentication.
- Potential consequences: session/data theft from other users' browser contexts, redirection to phishing or malicious sites, defacement of the public wall, or display of harmful/abusive content to a vulnerable user base (self-harm, crisis-related audience).
- Session cookies on this platform are correctly flagged `HttpOnly`, which prevents direct cookie theft via `document.cookie` from this vector — a partial mitigating factor — but does not prevent the other impacts above (DOM manipulation, redirection, credential phishing via injected fake login forms, etc.).

### Steps to Reproduce (Not Yet Executed — Documented for Planning Only)

> Note: This test was planned but intentionally **not executed** against the live production system to avoid introducing a confirmed live XSS payload before a fix is available. Reproduction should be performed against a staging/cloned environment.

1. Submit a story via the submission form (or directly via the TS-001 bypass) with content such as:
   ```html
   <img src=x onerror="alert('xss-test')">
   ```
2. Load the public community wall (`#story-wall`).
3. Observe whether the script executes (alert fires) rather than being rendered as literal text.

### Remediation (Recommended, Not Yet Implemented)

1. **Client-side:** HTML-escape all dynamic fields (`content_raw`, `display_name`, `displayTag`) before insertion, e.g., via a `textContent`-based escaping helper, rather than raw interpolation into `innerHTML`.
2. **Server-side (primary control):** Sanitize or encode submitted fields in `submit_story.php` before persisting to the database. Never rely on client-side escaping alone, since the API can be called directly (see TS-001).
3. **Defense in depth:** Implement a strict `Content-Security-Policy` (currently absent sitewide — see related header hardening finding) with a restrictive `script-src` to limit the blast radius of any future injection that slips past input handling.

---

## Related Finding: Sitewide Missing Security Headers

Independent of TS-001/TS-002, the following headers were found absent across the main domain and all tested subdomains (`admin.`, `counselor.`, `facilitators.`, `security.`, `student.`, `teens.`, `uni.`):

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `Referrer-Policy`
- `Permissions-Policy`

The main domain carries partial protection (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`), but this is **not present on any subdomain**, including `admin.trueselfgiveback.com`. A prior attempt to deploy these headers (specifically CSP) caused the site to break, due to the page's reliance on inline `<script>`/`<style>` blocks, inline event handlers, and multiple third-party script/font origins (Google Fonts, cdnjs, jsdelivr). Remediation requires a CSP tailored to these actual dependencies, deployed first in `Content-Security-Policy-Report-Only` mode and validated before enforcement.

**Status:** Open — Not yet remediated.

---

## Overall Assessment Status

All findings in this document remain **unremediated at time of writing**. This document is maintained as part of an ongoing, honest vulnerability tracking process rather than a closed-out report. Given the nature of the platform's user base, TS-001 and TS-002 are prioritized as the highest-urgency items for remediation.

| Finding | Severity | Status |
|---|---|---|
| TS-001 — Broken Access Control (submission endpoint) | High | 🔴 Open |
| TS-002 — Stored XSS (community wall) | High | 🔴 Open |
| Sitewide missing security headers | Medium | 🔴 Open |
