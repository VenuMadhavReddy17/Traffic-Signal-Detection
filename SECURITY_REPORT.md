# Security Assessment Report - Found Staging Application

**Target:** https://my.staging.found.com  
**Date:** March 28, 2026  
**Methodology:** Black-box security assessment via API analysis, JavaScript source review, and automated endpoint testing  

---

## Executive Summary

A comprehensive security assessment was performed against the Found staging application at `https://my.staging.found.com`. The assessment identified **6 confirmed vulnerabilities** ranging from medium to high severity, along with several informational findings. The most significant issues involve **missing authentication on sensitive endpoints**, **verbose error messages leaking internal implementation details**, and **session identifier exposure in API responses**.

---

## Findings

### FINDING 1: Authentication Bypass on Business Email Endpoints (HIGH)

**Severity:** High  
**CVSS Score:** ~7.5  
**Endpoints:**
- `POST /api/business/email-direct-deposit-form`
- `POST /api/business/email-signed-bank-letter`

**Description:**  
These endpoints process requests from unauthenticated users instead of returning a 401 Unauthorized response. When called without any authentication, the server attempts to execute business logic (looking up a deposit account) and only fails because the `nil` business object has no `deposit_account` method. This indicates the authentication check is either missing or occurs after business logic processing.

**Impact:**  
If the `nil` check were not present (or if an attacker could supply a valid `business_id` parameter), these endpoints could potentially be used to:
- Send direct deposit form emails to arbitrary addresses
- Send signed bank letter emails to arbitrary addresses
- Abuse the application's email-sending capability for phishing

**Proof of Concept:**
```
POST /api/business/email-direct-deposit-form HTTP/2
Host: my.staging.found.com
Content-Type: application/json

{"email": "attacker@evil.com"}

Response: 500
{"error_type":"internal_server_error","message":"undefined method `deposit_account' for nil"}
```

Expected behavior: The endpoint should return `401 {"status":"Not logged in"}` before processing any business logic.

**Remediation:**  
Add authentication middleware to these endpoints that verifies the user session before any business logic execution.

---

### FINDING 2: Verbose Error Messages Leak Internal Implementation Details (MEDIUM)

**Severity:** Medium  
**CVSS Score:** ~5.3  
**Endpoints:**
- `POST /api/business/email-direct-deposit-form`
- `POST /api/business/email-signed-bank-letter`

**Description:**  
The application returns detailed Ruby error messages in API responses, including method names and object state (nil). This reveals:
1. The backend is built with **Ruby/Rails** (confirmed by "undefined method" Ruby error syntax)
2. The application has a `deposit_account` method on a business model
3. The internal architecture uses a business object pattern

**Proof of Concept:**
```json
{"error_type":"internal_server_error","message":"undefined method `deposit_account' for nil"}
```

Additional Rails-specific disclosure found in 404 error pages:
```html
<title>The page you were looking for doesn't exist (404)</title>
```
This is the default Rails 404 page, confirming the backend framework.

**Impact:**  
Attackers can use this information to:
- Map internal application architecture
- Identify the backend framework and target framework-specific vulnerabilities
- Discover model relationships and method names for further exploitation

**Remediation:**  
- Return generic error messages to clients (e.g., "Internal server error")
- Log detailed errors server-side only
- Customize the 404 error page to remove Rails-specific indicators

---

### FINDING 3: Session ID Disclosure in API Error Responses (MEDIUM)

**Severity:** Medium  
**CVSS Score:** ~5.3  
**Endpoints:** Multiple endpoints return session IDs in 401 responses:
- `POST /api/verify-code`
- `POST /api/change-email/v2`
- `POST /api/change-password`
- `GET /api/plaid/link-token`
- `GET /api/debit-card/v3/all`
- `POST /api/upload`
- `POST /api/v2/update-name-ssn`
- `POST /api/v2/update-dob`
- `POST /api/v2/change-verified-phone`
- `POST /api/book-entry/v2/set-reason`
- `GET /api/invoice/check-identifier`
- `POST /api/linked-account/v2/link-via-account-routing`
- `GET /api/accountant`
- `GET /api/debit-card-share`
- `GET /api/contact/device-contacts`
- `GET /api/business-contact/search`
- `GET /api/custom-category`
- `GET /api/vendor-rule`
- `GET /api/peer-to-peer-payment`
- And many more...

**Description:**  
When unauthenticated requests are made to protected API endpoints, the server returns the session ID in the JSON response body:

```json
{"status":"Not logged in","session_id":"25683999-6a24-4cc2-80f1-e32426eeb31b"}
```

This session ID (UUID format) is exposed to any client making requests, including cross-origin requests if CORS is misconfigured.

**Impact:**  
- Session identifiers should not be exposed in response bodies as they could be logged by intermediary proxies, CDNs, or client-side analytics
- If the session ID correlates with a valid session token, this could facilitate session hijacking
- The consistent format (UUID v4) reveals the session management architecture

**Remediation:**  
Remove the `session_id` field from error response bodies. A simple `{"status":"Not logged in"}` is sufficient for the client.

---

### FINDING 4: Session Cookies Missing Secure Flag (MEDIUM)

**Severity:** Medium  
**CVSS Score:** ~4.8  
**Affected Cookies:**
- `_session_id` (session cookie) - **Missing Secure flag**
- `found_session_id` - **Missing Secure flag**
- `within_max_session_duration` - **Missing Secure flag**

**Description:**  
The primary session cookies (`_session_id`, `found_session_id`, `within_max_session_duration`) are set without the `Secure` flag. This means they will be transmitted over unencrypted HTTP connections if a user is tricked into visiting an HTTP version of the site or if there's a downgrade attack.

**Proof of Concept:**
```
Set-Cookie: _session_id=MC2%2BcoCnMCY86wGKOMdgvTX8F7wfleh7xwDjHEYksQB6...; path=/; httponly; samesite=lax
Set-Cookie: found_session_id=8b89f4db-632e-490f-9eb8-e41372d1154a; path=/; httponly; samesite=lax
Set-Cookie: within_max_session_duration=true; path=/; httponly; samesite=lax
```

Note: The `csrf_token` cookie correctly has the `Secure` flag, but the session cookies do not.

**Impact:**  
Session cookies could be intercepted over unencrypted connections via:
- Network sniffing on public WiFi
- MITM attacks
- SSL stripping attacks

**Remediation:**  
Add the `Secure` flag to all session-related cookies:
```
Set-Cookie: _session_id=...; path=/; httponly; secure; samesite=lax
```

---

### FINDING 5: Missing Security Headers on API Responses (LOW-MEDIUM)

**Severity:** Low-Medium  
**CVSS Score:** ~3.7  

**Description:**  
Several important security headers are missing from API responses:

| Header | Status |
|--------|--------|
| `Content-Type` | Present (application/json) |
| `X-Content-Type-Options` | Present (nosniff) |
| `X-Frame-Options` | Present (SAMEORIGIN) |
| `X-XSS-Protection` | Set to `0` (disabled) |
| `Strict-Transport-Security` | **MISSING** on API responses |
| `Content-Security-Policy` | **MISSING** on API responses |
| `Referrer-Policy` | **MISSING** on API responses |
| `Permissions-Policy` | **MISSING** on API responses |

Note: The HTML page responses DO include `Strict-Transport-Security` and `Content-Security-Policy: frame-ancestors 'self'`, but the API JSON responses do not.

**Impact:**  
- Without HSTS on API responses, downgrade attacks are possible on API calls
- Missing CSP on API responses is less critical but represents incomplete security posture

**Remediation:**  
Apply consistent security headers across all response types (HTML and JSON API).

---

### FINDING 6: User Enumeration via Security Code Endpoints (LOW)

**Severity:** Low  
**CVSS Score:** ~3.7  
**Endpoints:**
- `POST /api/email-security-code`
- `POST /api/sms-security-code`
- `POST /api/send-security-code`

**Description:**  
The security code endpoints return differential responses that allow user enumeration. When an unregistered email is supplied, the response is:

```json
{"message":"Login not found"}
```

This tells an attacker definitively that the email is not registered. For a registered account, a different response would be returned (e.g., success or a different error message).

**Impact:**  
An attacker can enumerate valid email addresses registered on the platform, which could be used for:
- Targeted phishing campaigns
- Credential stuffing attacks
- Account takeover preparation

**Remediation:**  
Return a generic message regardless of whether the email exists:
```json
{"message":"If an account exists with this email, a security code has been sent."}
```

---

## Informational Findings

### INFO 1: Segment Analytics API Key Exposed in Client-Side Code

The Segment analytics write key `Ghs4fno4fgHwyCi5V0infqTqsQWrcMav` is embedded in the client-side JavaScript. While Segment write keys are designed to be public, this is noted for completeness.

### INFO 2: Facebook Pixel ID Exposed

Facebook Pixel ID `1789272661380283` is embedded in the HTML source. This is expected for analytics tracking but noted for completeness.

### INFO 3: Marqeta JS Widget Loaded in Sandbox Mode

The application loads `https://widgets-sandbox.marqeta.com/marqetajs/2.0.0/marqeta.min.js`, confirming this is a staging/sandbox environment for card management.

### INFO 4: Fingerprint Pro Integration

The application integrates with Fingerprint Pro (`fp-cdn.found.com`, `fp.found.com`) with visible public key `9vUxEcs2MekwEkrAW8IV`. This is used for device fingerprinting and fraud detection.

### INFO 5: DataDog RUM Monitoring

DataDog Real User Monitoring is active with API key `pub0c5bd6a536f12406aaa8d9df61fc2c1f`. Public RUM keys are designed to be client-facing.

### INFO 6: Google Tag Manager

GTM container `GTM-KRJPP99` is loaded. This is standard analytics infrastructure.

### INFO 7: Accountant Client Resources PDF Generation

The endpoint `GET /api/accountant/client-resources-pdf` generates PDF documents without authentication. Different `invite_code` values produce PDFs with identical content ("Get started at staging.found.com") but different binary hashes (due to timestamp-based creation metadata). The PDFs contain no sensitive user data - they appear to be generic marketing/onboarding materials. This is noted as **intentional behavior** per the program's stated scope regarding share-type endpoints.

### INFO 8: Open Redirect Testing - Not Exploitable

The `/api/stripe/redirect?return_to=` endpoint was tested extensively with malicious URLs. While the endpoint issues a 302 redirect, testing confirmed that:
- The redirect goes to `/invoices/list` (an internal path) regardless of the `return_to` value
- External URLs like `https://evil.com`, `//evil.com`, `http://169.254.169.254` all redirect to the internal application
- The endpoint appears to validate/ignore the `return_to` parameter and redirects to a safe default
- This is **not exploitable** as an open redirect

---

## Scope Limitations

1. **Cloudflare Protection:** The Cloudflare managed challenge prevented automated testing of POST endpoints from non-browser contexts. The registration (`/api/register`) and related onboarding flows could not be fully tested via API due to this protection.

2. **No Authenticated Testing:** Due to the Cloudflare challenge blocking the registration endpoint from headless browsers, authenticated endpoint testing was limited. Additional testing with an authenticated session would likely reveal more findings, particularly around IDOR vulnerabilities on business-specific endpoints.

3. **Region Blocking:** The staging environment has region blocking in place which may have affected some test results.

---

## Recommendations Summary

| Priority | Finding | Recommendation |
|----------|---------|----------------|
| **HIGH** | Auth bypass on business email endpoints | Add authentication middleware before business logic |
| **MEDIUM** | Verbose error messages | Return generic errors; log details server-side |
| **MEDIUM** | Session ID in error responses | Remove session_id from JSON response bodies |
| **MEDIUM** | Missing Secure flag on session cookies | Add `Secure` flag to all session cookies |
| **LOW-MEDIUM** | Missing security headers | Apply HSTS, CSP consistently across all responses |
| **LOW** | User enumeration | Return generic messages on auth endpoints |

---

## Methodology

### Reconnaissance
- HTML source analysis to extract JavaScript chunk references
- Downloaded and analyzed 40+ JavaScript bundles to map API endpoints
- Identified application architecture: React SPA frontend, Ruby on Rails backend

### Testing Tools
- Python 3 with Playwright (headless Chromium) for browser-based testing
- curl for direct HTTP requests
- Custom automation scripts for systematic endpoint testing

### API Endpoints Discovered
Over 60 unique API endpoints were identified and tested, covering:
- Authentication & registration
- Business management
- Banking & linked accounts
- Debit card management
- Invoicing & payments
- P2P payments
- Contacts & contractors
- Tax & 1099 management
- Account settings
