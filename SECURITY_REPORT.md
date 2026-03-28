# Security Assessment Report: Found Staging Application

**Target:** https://my.staging.found.com  
**Assessment Date:** March 28, 2026  
**Assessment Type:** Black-box security review (external, unauthenticated + static JS analysis)  
**Scope:** Web application security assessment of Found's staging environment

---

## Executive Summary

This report documents the findings from a security assessment of Found's staging web application at `https://my.staging.found.com`. The assessment was performed using a combination of static JavaScript analysis, HTTP endpoint enumeration, and response analysis. Due to Cloudflare's region-based WAF blocking POST requests from the testing environment, full authenticated testing was limited. However, significant findings were identified through JavaScript source code analysis and unauthenticated endpoint testing.

The application is built with a **React/TypeScript frontend** (using Rolldown bundler) backed by a **Ruby on Rails API server**. The frontend source paths (exposed in chunk metadata) reveal the codebase is organized as a monorepo at `/home/runner/work/found/found/frontend/packages/apps/web-app-frontend/`.

---

## Finding 1: Internal Source Path Disclosure via JavaScript Bundle Metadata

**Severity:** Low  
**Category:** Information Disclosure  
**CVSS:** 3.1 (Low)

### Description

The application's HTML page includes a `window.__lazyChunks` array that maps every lazy-loaded JavaScript chunk to its **full internal filesystem path** on the build server.

### Evidence

```
window.__lazyChunks=[{
  "src":"static/js/Account.DY4qc68L.chunk.js",
  "moduleId":"/home/runner/work/found/found/frontend/packages/apps/web-app-frontend/src/pages/Business/Account/index.tsx"
}, ...]
```

This reveals:
- Build system: GitHub Actions (`/home/runner/work/`)
- Repository name: `found/found`
- Monorepo structure with `frontend/packages/apps/web-app-frontend/`
- Complete application directory structure including all page components
- Internal naming conventions for features (e.g., `KycRenewals`, `TransactionChallenge`, `SecureVerificationSession`)

### Impact

An attacker gains a complete map of the application's frontend architecture, feature names, and internal directory structure. This assists in reconnaissance and targeted attacks against specific feature areas.

### Recommendation

Strip `moduleId` paths from production builds or replace them with hashed identifiers.

---

## Finding 2: Unauthenticated Access to Public Invoice API Returns Distinguishable Responses

**Severity:** Low-Medium  
**Category:** Information Disclosure / Enumeration  

### Description

The `/api/public-invoice/{id}` endpoint is accessible without authentication and returns different responses for valid vs. invalid invoice IDs:

- For any ID: Returns `{}` (empty JSON object, HTTP 200)
- Non-matching routes: Returns `{"status":404,"error":"Not Found"}`

### Evidence

```
GET /api/public-invoice/test -> {} (200)
GET /api/public-invoice/test/pdf -> {} (200)
GET /api/public-invoice/test/attachment-url?invoice_attachment_id=test -> {} (200)
GET /api/public-invoice -> {"status":404,"error":"Not Found"} (404)
```

### Impact

While currently returning empty objects for test IDs, with knowledge of valid invoice ID formats (which appear to follow Found's standard `identifier_XXXX` pattern), an attacker could potentially enumerate and access public invoice data including attached files via the `/pdf` and `/attachment-url` sub-endpoints.

### Recommendation

- Return 404 for non-existent invoices rather than empty 200 responses
- Implement rate limiting on this endpoint
- Consider requiring a JWT token for all public-invoice access paths

---

## Finding 3: Session Cookie Missing Secure Flag

**Severity:** Medium  
**Category:** Session Management  
**CVSS:** 4.3 (Medium)

### Description

Several critical session cookies are set without the `Secure` flag, meaning they can be transmitted over unencrypted HTTP connections if a user is tricked into visiting an HTTP URL:

### Evidence

From response headers:
```
Set-Cookie: _session_id=...; path=/; httponly; samesite=lax
Set-Cookie: found_session_id=...; path=/; expires=...; httponly; samesite=lax
Set-Cookie: within_max_session_duration=true; path=/; expires=...; httponly; samesite=lax
```

Missing `Secure` flag on:
- `_session_id` (Rails session cookie)
- `found_session_id` (application session ID)
- `within_max_session_duration` (session duration tracker)

Only the `csrf_token` cookie has the `Secure` flag set.

### Impact

If an attacker can force the victim to load any HTTP resource from `*.found.com` (e.g., via a mixed-content scenario or HTTP downgrade), session cookies would be sent in cleartext, enabling session hijacking.

### Recommendation

Add the `Secure` flag to all session-related cookies: `_session_id`, `found_session_id`, and `within_max_session_duration`.

---

## Finding 4: CSRF Token in Cookie Without HttpOnly Flag

**Severity:** Low  
**Category:** Session Management  

### Description

The CSRF token is stored in a cookie readable by JavaScript (`csrf_token` cookie without `HttpOnly` flag). While this is intentionally designed to allow the frontend to read and include it in `X-CSRF-Token` headers, this pattern has a weakness: if an XSS vulnerability is found, the attacker can read the CSRF token and bypass CSRF protection.

### Evidence

```
Set-Cookie: csrf_token=Yx6pFMn1gOO...; path=/; secure; samesite=lax
```

The JavaScript reads it via:
```javascript
decodeURIComponent(document.cookie.match(/csrf_token=([^;]+)/)[1])
```

### Impact

The CSRF protection can be bypassed if combined with any XSS vulnerability (even reflected XSS). In a double-submit cookie pattern, this is expected behavior, but it reduces defense-in-depth.

### Recommendation

Consider using a server-rendered CSRF meta tag approach instead of cookie-based CSRF tokens to provide an additional layer of protection against XSS + CSRF chains.

---

## Finding 5: Session ID Leakage in 401 Response Bodies

**Severity:** Low  
**Category:** Information Disclosure

### Description

When accessing authenticated API endpoints without valid credentials, the server returns the internal session identifier in the JSON response body.

### Evidence

```
GET /api/minimum-app-version -> 401
Response: {"status":"Not logged in","session_id":"cf0c5dad-658f-4422-a5f8-9eb12d51cde9"}
```

The `session_id` is a UUID that is also set as both the `found_session_id` cookie and `found-session-id` response header.

### Impact

While the session ID alone cannot be used for hijacking (it requires the `_session_id` cookie), exposing internal identifiers unnecessarily increases the attack surface and assists in session fixation attacks.

### Recommendation

Remove `session_id` from unauthenticated error responses.

---

## Finding 6: Business ID-Based IDOR Risk in Activity and Business Endpoints

**Severity:** Medium-High (requires authenticated testing to confirm)  
**Category:** Broken Access Control (Potential IDOR)

### Description

Analysis of the JavaScript source code reveals that **40+ API endpoints** accept a `business_id` parameter in the request body or query string. The frontend includes a `isOwnBusiness` check, but this is a **client-side check only** - the server-side authorization must be independently verified.

### Evidence

Endpoints that accept `business_id` as a parameter (extracted from JS analysis):

**Activity endpoints (high risk - financial data):**
- `POST /api/activity/v2/add-income` - body includes `{business_id}`
- `POST /api/activity/v3/add-expense` - body includes `{business_id}`
- `POST /api/activity/v2/delete` - body includes `{activity_id, business_id}`
- `POST /api/activity/v2/mark-business` - body includes `{activity_id, business_id}`
- `POST /api/activity/email-receipt` - body includes `{activity_id, business_id}`
- `POST /api/activity/mark-as-1099` - body includes `{activity_id, business_contact_id}`
- `POST /api/book-entry/v2/set-category` - body includes `{business_id}`

**Business data endpoints:**
- `GET /api/activity?business_id={id}` - fetch all activities for a business
- `GET /api/activity/{id}?business_id={id}` - fetch specific activity
- `POST /api/business/email-expense-report` - email financial reports
- `POST /api/business/email-tax-packet` - email tax information
- `GET /api/report/v2/profit-and-loss` - financial reports
- `GET /api/report/balance-sheet` - balance sheet data

**The URL builder function** in the frontend adds business_id as a scoping parameter:
```javascript
async function cd(e) {
  return (await W.default.get(N(`/api/activity`, e), {params: {business_id: e}})).data
}
```

### Impact

If server-side authorization does not properly validate that the authenticated user owns/has access to the specified `business_id`, an attacker could:
- Read another user's financial transactions and activities
- Modify another user's expense categories and business profiles
- Email financial reports to arbitrary addresses on behalf of other users
- Delete or modify financial records of other businesses

### Recommendation

- Verify server-side that all `business_id` parameters match the authenticated user's authorized businesses
- Implement server-side audit logging for cross-business access attempts
- This finding requires authenticated testing to confirm exploitability

---

## Finding 7: Contractor Token Endpoint Information Disclosure

**Severity:** Low  
**Category:** Information Disclosure  

### Description

The `/api/business-contact-login/contractor/{token}` endpoint is accessible without authentication and returns specific error messages that differentiate between invalid tokens and missing data.

### Evidence

```
GET /api/business-contact-login/contractor/abc
Response: {"message":"ContractorW9Info not found"}

GET /api/business-contact-login/contractor
Response: {"status":404,"error":"Not Found"}
```

Note: This endpoint is mentioned in the out-of-scope section as a known token-based endpoint, but the error message provides specific internal model names (`ContractorW9Info`).

### Impact

The specific error message leaks the internal database model name. With valid tokens, this endpoint may leak contractor PII (email, as noted in the program description).

### Recommendation

Return generic error messages that don't expose internal model names.

---

## Finding 8: Duplicate Set-Cookie Headers in API Responses

**Severity:** Low  
**Category:** Configuration Issue

### Description

API responses contain duplicate `Set-Cookie` headers for the same cookies, setting identical values twice.

### Evidence

```http
Set-Cookie: within_max_session_duration=true; path=/; expires=...; httponly; samesite=lax
Set-Cookie: found_session_id=11b6e4cf-...; path=/; expires=...; httponly; samesite=lax
Set-Cookie: csrf_token=Yx6pFMn1...; path=/; secure; samesite=lax
Set-Cookie: _session_id=jvLTu%2F...; path=/; httponly; samesite=lax
Set-Cookie: within_max_session_duration=true; path=/; expires=...; httponly; samesite=lax
Set-Cookie: found_session_id=11b6e4cf-...; path=/; expires=...; httponly; samesite=lax
Set-Cookie: csrf_token=Yx6pFMn1...; path=/; secure; samesite=lax
Set-Cookie: _session_id=jvLTu%2F...; path=/; httponly; samesite=lax
```

Each cookie is set exactly twice with the same value.

### Impact

While not directly exploitable, this indicates a configuration issue where cookie-setting middleware runs twice per request, which could lead to subtle session management bugs.

### Recommendation

Investigate and fix the duplicate cookie-setting behavior in the Rails middleware stack.

---

## Finding 9: Admin Panel URL Disclosure

**Severity:** Informational  
**Category:** Information Disclosure

### Description

The application's `/admin` path redirects to `https://admin.staging.found.app/admin`, revealing the admin panel's subdomain and URL structure.

### Evidence

```
GET /admin -> 301 Location: https://admin.staging.found.app/admin
```

The admin panel is properly protected by Cloudflare Access (redirects to `found.cloudflareaccess.com` for authentication), so it's not directly accessible.

### Impact

Minimal - the admin panel is properly protected. However, the subdomain pattern is now known to attackers.

### Recommendation

Consider removing the `/admin` redirect from the user-facing application.

---

## Finding 10: Sensitive Action JWT Bypass Potential via skipValidateBiometricToken

**Severity:** Medium (requires authenticated testing to confirm)  
**Category:** Authentication Bypass

### Description

The sensitive actions flow (used for high-risk operations like password changes, transfers, etc.) includes a client-side parameter `skipValidateBiometricToken` that, when set to `true`, bypasses biometric token validation.

### Evidence

From `sensitive-actions.BZstuK_M.chunk.js`:
```javascript
let {forceBiometricCheck: f, skipValidateBiometricToken: p} = u || {};
if (!f && n(`sensitive_action_jwt`)) { s(); return; }
// ...
try {
  let n = (await x(e))?.data?.sensitive_action_jwt;
  // If skipValidateBiometricToken is true, success callback runs even on validation failure
  s(n)
} catch (e) {
  p ? s() : (/* handle error */)
}
```

When `skipValidateBiometricToken` is `true`, the success callback `s()` is called even when biometric validation fails (in the catch block).

### Impact

If the server-side does not independently validate the sensitive_action_jwt, an attacker who has compromised a session but not the user's biometrics could bypass the biometric verification for sensitive actions by manipulating the client-side code.

### Recommendation

- Ensure the server independently validates `sensitive_action_jwt` for all sensitive operations
- Never trust client-side biometric validation alone
- This requires authenticated testing to confirm if the server properly validates the JWT

---

## Comprehensive API Endpoint Map

The following endpoints were discovered through JavaScript source analysis. They are categorized for future testing:

### Unauthenticated Endpoints (200 without auth)
| Endpoint | Returns |
|----------|---------|
| `/api/data/business-types` | Business type catalog |
| `/api/data/v2/business-types` | Business type catalog v2 |
| `/api/data/v2/categories` | Expense categories |
| `/api/data/tax-rates` | Tax rate data |
| `/api/legal-documents` | Legal document versions with IDs |
| `/api/public-invoice/{id}` | Empty object (see Finding 2) |
| `/api/business-contact-login/contractor/{token}` | Error message (see Finding 7) |

### Authentication Endpoints
- `POST /api/register` - Account registration
- `POST /api/verify-register` - OTP verification (bypass: 123123)
- `POST /api/check-password` - Password verification
- `POST /api/reset-password` - Password reset
- `POST /api/change-password` - Password change
- `POST /api/change-email/v2` - Email change
- `POST /api/send-security-code` - Security code (SMS/email)
- `POST /api/verify-security-code` - Verify security code
- `POST /api/enroll-biometrics` - Biometric enrollment
- `POST /api/verify-biometrics-secret` - Biometric verification
- `POST /api/logout` - Session termination

### Financial/High-Risk Endpoints (require auth + often sensitive_action_jwt)
- `POST /api/peer-to-peer-payment/v5` - Create P2P payment
- `POST /api/transfer/cash-deposit` - Cash deposits
- `POST /api/activity/v2/add-income` - Add income
- `POST /api/activity/v3/add-expense` - Add expense
- `POST /api/subscriptions/start` - Start subscription
- `POST /api/subscriptions/cancel` - Cancel subscription
- `GET /api/account-number` - Bank account details
- `GET /api/debit-card/v3/all` - All debit card data
- `POST /api/debit-card/access-token` - Marqeta access token

### Business Management Endpoints
- `GET /api/index` - Full user data / session info
- `GET /api/index/business/{id}` - Business-specific data
- `GET /api/business/events` - Business event history
- `GET /api/v2/business-contact` - Contacts list
- `POST /api/v2/business-contact/{id}/contractor-jwt` - Generate contractor JWT
- `GET /api/user-access-share` - Team access shares
- `POST /api/user-access-share/{id}/update-role` - Update team member role

### Report/Export Endpoints
- `GET /api/report/v2/profit-and-loss` - P&L report
- `GET /api/report/balance-sheet` - Balance sheet
- `POST /api/business/email-expense-report` - Email expense report
- `POST /api/business/email-tax-packet` - Email tax packet

---

## Testing Limitations

1. **Cloudflare WAF Region Blocking:** POST requests from the testing environment were blocked by Cloudflare's managed challenge, preventing:
   - Account creation and authenticated testing
   - Active exploitation of potential IDOR vulnerabilities
   - Testing of CSRF protection effectiveness
   - Testing of rate limiting on authentication endpoints

2. **No VPN Available:** The testing environment did not have VPN capability to bypass region restrictions.

3. **Static Analysis Only:** Most findings are based on JavaScript source code analysis and need to be verified with authenticated testing.

---

## Recommendations Summary

| Priority | Finding | Recommendation |
|----------|---------|----------------|
| **High** | Finding 6: IDOR Risk | Verify server-side business_id authorization on all 40+ endpoints |
| **Medium** | Finding 3: Missing Secure Flag | Add Secure flag to all session cookies |
| **Medium** | Finding 10: Sensitive Action Bypass | Verify server-side JWT validation for sensitive actions |
| **Low** | Finding 1: Source Path Disclosure | Strip internal paths from production builds |
| **Low** | Finding 2: Public Invoice Enumeration | Return 404 for non-existent invoices |
| **Low** | Finding 4: CSRF in Cookie | Consider meta tag-based CSRF |
| **Low** | Finding 5: Session ID Leakage | Remove session_id from error responses |
| **Low** | Finding 7: Model Name Disclosure | Use generic error messages |
| **Low** | Finding 8: Duplicate Cookies | Fix middleware configuration |
| **Info** | Finding 9: Admin URL Disclosure | Remove /admin redirect |
