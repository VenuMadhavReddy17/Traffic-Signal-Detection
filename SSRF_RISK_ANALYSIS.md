# SSRF Risk Analysis Report

**Target:** `https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com/app_settings/app_settings/69c8d257629242005dba8746?locale=en`

**Date:** 2026-03-29

**Scope:** Authorized bug bounty security testing — observation and analysis only

**Methodology:** Static analysis of endpoint structure, parameter identification, feature-based risk mapping using OWASP SSRF Prevention guidelines

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

## 2. SSRF-Susceptible Features in App Settings Dashboards

Based on Braze's documented feature set and common patterns in dashboard-type applications, the following features within or reachable from app settings pages may accept URL inputs that trigger server-side HTTP requests:

### 2.1 Webhook Configuration

| Field | Detail |
|-------|--------|
| **Endpoint** | `/app_settings/...` — Webhook settings are often accessible from app configuration |
| **Parameter** | `webhook_url`, `url`, `endpoint_url`, `callback_url` |
| **Observation** | Braze webhooks allow users to specify arbitrary HTTP endpoints. When a webhook is configured, the server stores the URL and later makes server-side HTTP requests to it during campaign sends or test sends. |
| **Risk Level** | **Likely** |
| **Reasoning** | Webhook URLs are user-controlled and result in server-side outbound HTTP requests by design. If the input validation does not restrict requests to external-only, public IP ranges, a user could supply internal network addresses (e.g., `http://169.254.169.254/latest/meta-data/`, `http://127.0.0.1`, or internal Kubernetes service names like `http://metadata.google.internal/`). The "Test Send" feature, if available, would trigger the request immediately rather than requiring a full campaign. |

### 2.2 Connected Content URLs

| Field | Detail |
|-------|--------|
| **Endpoint** | Campaign/message composer (reachable from app settings context) |
| **Parameter** | URL within `{% connected_content <URL> %}` Liquid tags |
| **Observation** | Braze Connected Content makes server-side HTTP GET requests to user-supplied URLs at message send time. The documentation confirms: "Insert any information accessible by API directly into messages you send to users. You can pull content either directly from your web server or from publicly accessible APIs." |
| **Risk Level** | **Likely** |
| **Reasoning** | Connected Content is an explicit server-side fetch mechanism. URLs are provided by the dashboard user and fetched by Braze's backend. If URL validation does not enforce a blocklist of internal/private IP ranges and cloud metadata endpoints, this is a direct SSRF vector. Testing can be done by supplying a controlled external collaborator domain as the Connected Content URL and observing the inbound request from Braze's infrastructure. |

### 2.3 Push Notification Icon / Image URLs

| Field | Detail |
|-------|--------|
| **Endpoint** | App settings — push notification configuration |
| **Parameter** | `icon_url`, `image_url`, `badge_url`, `large_icon_url` |
| **Observation** | Push notification settings may include fields for custom notification icons or images specified by URL. If the server fetches these resources to validate, resize, or cache them, user-controlled URLs flow into server-side HTTP requests. |
| **Risk Level** | **Possible** |
| **Reasoning** | Image/icon URLs in settings are commonly fetched server-side for validation or proxy purposes. Whether the server fetches these at configuration time (immediately) or only at send time needs to be verified. If the server fetches on save, it presents an immediate SSRF opportunity. |

### 2.4 Custom API Endpoint / Data Integration URLs

| Field | Detail |
|-------|--------|
| **Endpoint** | App settings — integrations or data export configuration |
| **Parameter** | `api_endpoint`, `api_url`, `data_url`, `export_url`, `s3_url`, `gcs_url` |
| **Observation** | App settings pages may contain fields for configuring custom REST API endpoints for data feeds, Currents data export, or partner integrations. These typically require the server to connect to the specified URL to validate credentials or fetch metadata. |
| **Risk Level** | **Possible** |
| **Reasoning** | Integration setup flows that perform a "Test Connection" or "Validate" step make immediate server-side requests to user-controlled URLs. The risk depends on whether such features exist on this specific settings page and whether they perform server-side validation. |

### 2.5 Email Settings — Custom Tracking Domain / Link Redirect

| Field | Detail |
|-------|--------|
| **Endpoint** | App settings — email configuration |
| **Parameter** | `tracking_domain`, `redirect_url`, `click_tracking_url` |
| **Observation** | Email configuration may include custom tracking domain settings. If the server validates these domains by making HTTP requests, they could be SSRF vectors. |
| **Risk Level** | **Possible** |
| **Reasoning** | Domain validation typically uses DNS resolution rather than HTTP requests, but some implementations make HEAD or GET requests to verify the domain is reachable and properly configured. Risk depends on implementation. |

### 2.6 Content Card / In-App Message Image URLs

| Field | Detail |
|-------|--------|
| **Endpoint** | Settings or message composition |
| **Parameter** | `image_url`, `media_url`, `card_image` |
| **Observation** | Content cards and in-app messages accept image URLs. If the server fetches these for thumbnail generation, validation, or CDN caching at configuration time, the URL flows to a server-side request. |
| **Risk Level** | **Possible** |
| **Reasoning** | Similar to push notification icons. The distinction is whether the URL is only stored (client-side rendering) or also fetched server-side. Observation via a collaborator domain can confirm this. |

---

## 3. Suggested Safe Verification Techniques

These techniques are observation-only and aligned with authorized bug bounty testing:

### 3.1 Out-of-Band Interaction Testing

1. **Set up a collaborator domain** (e.g., Burp Collaborator, interact.sh, or a self-hosted DNS/HTTP listener)
2. For each URL-accepting field identified above, supply a unique collaborator subdomain:
   - `https://<unique-id>.your-collaborator.example.com`
3. **Observe** whether the Braze server makes DNS lookups or HTTP requests to your controlled domain
4. **Record** the timing (immediate on save vs. delayed on send), source IP, User-Agent, and any request headers

### 3.2 Behavioral Comparison

1. **Valid external URL**: Supply a known-reachable public URL and note the application response (success, preview generated, etc.)
2. **Non-routable internal URL**: Supply `http://192.168.1.1` or `http://10.0.0.1` and compare the error message
3. **Cloud metadata URL**: Supply `http://169.254.169.254/` and compare the error message
4. **Localhost**: Supply `http://127.0.0.1` or `http://localhost` and compare the error message
5. **Kubernetes internal**: Supply `http://kubernetes.default.svc` and compare the error message

If error messages differ between non-routable internal addresses and genuinely unreachable external addresses, it indicates the server is attempting the connection and its behavior varies based on network reachability — a strong SSRF indicator.

### 3.3 DNS Rebinding Check

1. Supply a domain that first resolves to a public IP, then rebinds to an internal IP
2. If the server follows the rebind, it indicates lack of DNS pinning protection

### 3.4 Redirect Chain Check

1. Supply a URL to your controlled server that returns a 302 redirect to an internal address
2. If the server follows the redirect, it indicates the SSRF protection (if any) only validates the initial URL

---

## 4. Findings Summary

| # | Endpoint / Feature | Parameter(s) | Risk Level | Key Observation |
|---|-------------------|-------------|------------|-----------------|
| 1 | Webhook Configuration | `webhook_url`, `url`, `callback_url` | **Likely** | Webhooks are designed to make server-side HTTP requests to user-specified URLs. Test sends trigger immediate requests. |
| 2 | Connected Content | URL in `{% connected_content %}` tag | **Likely** | Documented feature that makes server-side GET requests to arbitrary user-supplied URLs at send time. |
| 3 | Push Icon/Image URLs | `icon_url`, `image_url` | **Possible** | May trigger server-side fetch for validation or caching; needs verification via collaborator. |
| 4 | API/Integration URLs | `api_endpoint`, `api_url`, `export_url` | **Possible** | Integration setup with test/validate flows may make immediate server-side requests. |
| 5 | Email Tracking Domain | `tracking_domain`, `redirect_url` | **Possible** | Domain validation might involve HTTP requests; needs verification. |
| 6 | Content Card Images | `image_url`, `media_url` | **Possible** | Server-side fetch for thumbnailing or CDN caching is implementation-dependent. |

---

## 5. Infrastructure-Specific Considerations

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

## 6. Recommended Next Steps

1. **Prioritize** testing webhook URL and Connected Content features as they are the highest-likelihood SSRF vectors
2. **Deploy** an out-of-band interaction listener before testing
3. **Document** all server-initiated interactions (timestamps, source IPs, headers)
4. **Compare** error responses for internal vs. external URLs to fingerprint server-side fetch behavior
5. **Report** any confirmed server-side interaction to the bug bounty program with evidence

---

## 7. Disclaimer

This analysis is performed under authorized bug bounty scope. All techniques described are observation-based and non-exploitative. No internal resources were accessed. Findings are based on feature analysis, endpoint structure, and publicly available documentation.
