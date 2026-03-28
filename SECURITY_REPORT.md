# Security Assessment Report - Found Staging Application (my.staging.found.com)

**Assessment Date:** March 28, 2026  
**Target:** https://my.staging.found.com  
**Assessor:** Automated Security Assessment  

---

## Executive Summary

A security assessment was conducted on Found's staging web application at `https://my.staging.found.com`. The assessment identified several vulnerabilities and security concerns ranging from informational to medium severity. The application is a React SPA served by a Ruby on Rails backend, with Cloudflare protection in front.

---

## Findings

### FINDING 1: Verbose Error Messages Leaking Database Schema (Medium)

**Severity:** Medium  
**Endpoint:** `GET /api/public-download?file_id={any_value}`  
**Type:** Information Disclosure (CWE-209)

**Description:**  
The `/api/public-download` endpoint returns verbose error messages that reveal internal database schema information when provided with an invalid `file_id` parameter. The error response includes the exact ActiveRecord query structure.

**Proof of Concept:**

```
curl -s "https://my.staging.found.com/api/public-download?file_id=test"
```

**Response:**
```json
{
  "error_type": "internal_server_error",
  "message": "Couldn't find SavedFile with [WHERE `saved_files`.`token` = ? AND `saved_files`.`allow_download` = ? AND `saved_files`.`kind` IN (?, ?)]"
}
```

**Impact:**  
This reveals:
- The application uses a `saved_files` database table
- Files are identified by `token` column (not sequential IDs)
- There is an `allow_download` boolean/flag column
- There is a `kind` column with multiple allowed values
- The application uses ActiveRecord ORM (Ruby on Rails)

This information aids an attacker in understanding the data model and crafting more targeted attacks against the file system.

**Remediation:**  
Return a generic "Not Found" error (404) instead of the verbose internal server error. Never expose database query structures in error responses.

---

### FINDING 2: Session ID Disclosure in 401 Responses (Low)

**Severity:** Low  
**Endpoint:** Multiple authenticated API endpoints  
**Type:** Information Disclosure (CWE-200)

**Description:**  
When unauthenticated requests are made to authenticated API endpoints, the server returns a session ID in the JSON response body.

**Proof of Concept:**

```
curl -s "https://my.staging.found.com/api/account-number"
```

**Response:**
```json
{"status": "Not logged in", "session_id": "397f3436-3cc0-4c3c-bd05-5ac0e326b76c"}
```

**Affected Endpoints:** `/api/account-number`, `/api/debit-card/v3/all`, `/api/pockets`, `/api/subscriptions`, `/api/tax-settings`, `/api/user-access-share`, and likely all authenticated endpoints.

**Impact:**  
Session identifiers are leaked to unauthenticated users. While these appear to be UUID-format identifiers that may not directly correspond to exploitable session tokens, disclosing internal session tracking IDs provides information to attackers.

**Remediation:**  
Remove the `session_id` field from 401 error responses. Return only `{"status": "Not logged in"}` or similar.

---

### FINDING 3: Admin Panel URL Disclosure via Redirect (Low)

**Severity:** Low  
**Endpoint:** `GET /admin`  
**Type:** Information Disclosure (CWE-200)

**Description:**  
Accessing `/admin` on the staging application returns a 301 redirect that reveals the admin panel subdomain: `https://admin.staging.found.app/admin`. This confirms the existence and location of the administrative interface.

**Proof of Concept:**

```
curl -sI "https://my.staging.found.com/admin"
# Returns: Location: https://admin.staging.found.app/admin
```

**Impact:**  
This reveals the admin panel location, which could be targeted for further attacks (brute force, credential stuffing, etc.)

**Remediation:**  
Return a 404 on `/admin` instead of redirecting. If the redirect is required for internal use, restrict it to authenticated admin sessions only.

---

### FINDING 4: Internal Source Code Path Disclosure in JavaScript Bundles (Informational)

**Severity:** Informational  
**Location:** `/sitemap.xml`, JavaScript chunk metadata  
**Type:** Information Disclosure (CWE-200)

**Description:**  
The application's `sitemap.xml` and the `window.__lazyChunks` configuration in `index.html` expose the complete internal source code file paths of the application. These paths reveal the full CI/CD build directory structure.

**Example paths exposed:**

```
/home/runner/work/found/found/frontend/packages/apps/web-app-frontend/src/pages/Business/Account/index.tsx
/home/runner/work/found/found/frontend/packages/apps/web-app-frontend/src/sharedPages/Debug/index.tsx
/home/runner/work/found/found/frontend/packages/apps/web-app-frontend/src/pages/Login/index.tsx
```

**Impact:**  
Reveals:
- The application is built using GitHub Actions (path contains `/home/runner/work/`)
- The repository is named `found/found`
- The monorepo structure with `frontend/packages/apps/web-app-frontend/`
- All page component names and their organization
- The existence of a **Debug page** at `/debug` path

**Remediation:**  
Strip source paths from production/staging builds. Configure the build system to remove or anonymize `moduleId` paths.

---

### FINDING 5: Debug Page Available in Staging (Low)

**Severity:** Low  
**Location:** `/debug` (client-side route)  
**Type:** Improper Access Control (CWE-284)

**Description:**  
The JavaScript bundles reveal a Debug page component (`Debug.dGLuELOd.chunk.js`) that is loaded in the staging application. Analysis of the chunk reveals it provides functionality including:

- Generate test transactions (`/api/transaction/generate`)
- Create fake card transactions (`/api/transaction/fake-card-spend`)
- Create fake external transfers (`/api/transaction/fake-external-transfer`)
- Create fake cash deposits (`/api/transaction/fake-cash-deposit`)
- Switch between businesses (`/api/development/switch-business`)
- Create MCA offers (`/api/development/create-mca-offer`)
- Trigger KYC expiry (`/api/development/fake-kyc-expiry`)
- Simulate Marqeta 3DS webhooks
- Reset onboarding, create Persona inquiries
- **"Fake Onboarding"** option for creating test accounts quickly

While these backend endpoints appear to require authentication and return 403 for CSRF validation, the existence of these development/debug features in a staging environment that is intended for external security testing represents a risk.

**Backend endpoints tested:** All returned `403 - forbidden` for unauthenticated requests, indicating CSRF protection is active. However, for authenticated users, these development endpoints may be accessible.

**Remediation:**  
Ensure all `/api/development/*` and `/api/transaction/fake-*` endpoints require admin-level privileges, not just authentication. Consider removing the debug page from non-development environments entirely.

---

### FINDING 6: Cookies Missing Secure Attributes (Low)

**Severity:** Low  
**Type:** Insecure Cookie Configuration (CWE-614)

**Description:**  
Several application cookies are set without the `HttpOnly`, `Secure`, or `SameSite` attributes:

| Cookie | HttpOnly | Secure | SameSite | Domain |
|--------|----------|--------|----------|--------|
| `_found_avt` | No | No | Lax | .found.com |
| `ab.storage.sessionId.*` | No | No | Lax | .found.com |
| `ab.storage.deviceId.*` | No | No | Lax | .found.com |
| `_dd_s` | No | No | Strict | my.staging.found.com |
| `_gcl_au` | No | No | Lax | .found.com |

The `csrf_token` cookie, which is required to be read by JavaScript, is not set with `HttpOnly` (this is expected for CSRF token cookies that need to be read client-side). However, the `_found_avt` analytics/visitor tracking cookie and `ab.storage.*` (Braze analytics) cookies are accessible via JavaScript and scoped to the entire `.found.com` domain.

**Note:** This is listed as out-of-scope per the program rules ("Missing HttpOnly or Secure flags on cookies"), but is documented here for completeness.

---

### FINDING 7: Third-Party Service Identifiers Exposed (Informational)

**Severity:** Informational  
**Location:** `index.html` source, JavaScript bundles  
**Type:** Information Disclosure

**Description:**  
The following third-party service identifiers are exposed in the frontend code:

- **Facebook Pixel ID:** `1789272661380283`
- **Segment Analytics:** Snippet loaded from `cdn.segment.com`
- **Google Ads:** Conversion ID `AW-471805068`
- **DataDog RUM:** API Key `pub0c5bd6a536f12406aaa8d9df61fc2c1f` (public key, expected)
- **DataDog Beacon Token:** `2591fe25cfab4fd8900017a8dfe4a7ab`
- **Braze SDK:** Configured with server `sdk.iad-05.braze.com`
- **FingerprintJS:** Client-side fingerprinting active
- **Sardine:** Device ID fraud prevention (`sardine_device_id`)
- **Mapbox GL:** Map library loaded
- **Stripe Terminal:** Payment processing integration

While most of these are public-facing client IDs (not secrets), exposing the full set of third-party services provides attackers with intelligence about the technology stack.

---

### FINDING 8: Technology Stack Disclosure (Informational)

**Severity:** Informational  
**Type:** Information Disclosure

**Description:**  
The following technology details are disclosed through various responses:

| Component | Evidence |
|-----------|----------|
| **Ruby on Rails** | Default 404 error page (`public/404.html` comment), ActiveRecord errors, CSRF token pattern |
| **Cloudflare** | `server: cloudflare` header, `cf-ray` header, `__cf_bm` cookie |
| **Google Cloud** | `via: 1.1 google` header |
| **React** | SPA architecture, lazy-loaded chunks |
| **nginx** | GraphQL endpoint returns `nginx` error page |
| **Marqeta** | Debit card issuance (CSS for `.mq-notification`) |
| **Plaid** | Bank account linking |
| **Persona** | KYC/Identity verification |
| **Piermont Bank / Lead Bank** | Banking partners (from legal documents API) |

---

### FINDING 9: Potential XSS via dangerouslySetInnerHTML (Informational - Requires Further Investigation)

**Severity:** Informational (needs auth to verify)  
**Location:** Multiple React components  
**Type:** Potential Cross-Site Scripting (CWE-79)

**Description:**  
The JavaScript bundles contain at least 2 instances of `dangerouslySetInnerHTML` used with dynamic content in non-framework code:

```javascript
// Pattern found in subscription/promotion modals:
function Z({content:e}) {
  return typeof e == 'string' 
    ? r('div', {dangerouslySetInnerHTML: {__html: e}}, e) 
    : r('div', {children: e});
}
```

This pattern renders string content as raw HTML. If the `content` variable comes from user-controlled input or an API response that can be influenced by an attacker, this could lead to stored XSS.

**Impact:**  
Cannot be verified without an authenticated session to determine what data flows into these components. If API responses contain user-controlled data that gets rendered via `dangerouslySetInnerHTML`, it would be a stored XSS vulnerability.

**Remediation:**  
Audit all uses of `dangerouslySetInnerHTML` and ensure content is properly sanitized (e.g., using DOMPurify) before rendering.

---

### FINDING 10: Marqeta 3DS Webhook Endpoint Discovery (Informational)

**Severity:** Informational  
**Endpoint:** `POST /api/marqeta_3ds/fake_authentication_webhook`  
**Type:** Information Disclosure

**Description:**  
The fake Marqeta 3DS webhook endpoint returns a 404 instead of 403, suggesting the `/api/marqeta_3ds/` route namespace exists but may have different endpoints. Real webhook endpoints for card authentication could potentially be targeted.

```
POST /api/marqeta_3ds/fake_authentication_webhook: 404
POST /api/marqeta_3ds/fake_decision_webhook: (likely similar)
POST /api/marqeta_3ds/fake_result_webhook: (likely similar)
```

This suggests real webhook endpoints like `/api/marqeta_3ds/authentication_webhook`, `/api/marqeta_3ds/decision_webhook`, and `/api/marqeta_3ds/result_webhook` may exist. If these accept unsigned or improperly verified webhook payloads, they could be exploited.

---

## Summary of Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | Verbose Error Messages Leaking DB Schema | Medium |
| 2 | Session ID Disclosure in 401 Responses | Low |
| 3 | Admin Panel URL Disclosure via Redirect | Low |
| 4 | Internal Source Code Path Disclosure | Informational |
| 5 | Debug Page Available in Staging | Low |
| 6 | Cookies Missing Secure Attributes | Low (Out of Scope) |
| 7 | Third-Party Service Identifiers Exposed | Informational |
| 8 | Technology Stack Disclosure | Informational |
| 9 | Potential XSS via dangerouslySetInnerHTML | Informational |
| 10 | Marqeta 3DS Webhook Endpoint Discovery | Informational |

---

## Positive Security Observations

- **CSRF Protection:** All POST endpoints properly validate CSRF tokens (`X-CSRF-Token` header) and reject requests without valid tokens.
- **Authentication Enforcement:** All sensitive API endpoints properly return 401 for unauthenticated requests.
- **Development Endpoints Protected:** `/api/development/*` and `/api/transaction/fake-*` endpoints return 403 with CSRF validation.
- **Cloudflare WAF:** Automated requests with SQL injection payloads are blocked by Cloudflare.
- **Security Headers:** `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: frame-ancestors 'self'`, `Referrer-Policy: strict-origin-when-cross-origin`, `HSTS` are all properly set.
- **No Hardcoded Secrets:** No API keys, secret keys, or authentication tokens were found hardcoded in the JavaScript bundles (only expected public client-side IDs).

---

## Limitations

- **Cloudflare Challenge:** The Cloudflare managed challenge blocked automated registration and many POST-based tests. Creating an authenticated account was not possible from this environment, limiting the depth of authenticated testing.
- **Region Blocking:** Some tests may have been affected by region-based blocking on the staging environment.
- **No Source Code Access:** Assessment was performed externally via black-box testing of the staging application only.

---

## Recommendations

1. **Fix verbose error handling** on `/api/public-download` to return generic 404 errors
2. **Remove `session_id`** from 401 unauthenticated error responses
3. **Remove or restrict `/admin` redirect** to prevent admin panel URL disclosure
4. **Strip source paths** from production/staging JavaScript builds
5. **Audit `dangerouslySetInnerHTML`** usage for potential XSS
6. **Verify webhook endpoint security** for Marqeta 3DS callbacks
7. **Consider removing debug/development functionality** from staging if external testers have access
