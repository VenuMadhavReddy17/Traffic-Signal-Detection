# SSRF Risk Analysis Report

**Target:** `https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com/app_settings/app_settings/69c8d257629242005dba8746?locale=en`

**Date:** 2026-03-29

**Scope:** Authorized bug bounty testing — analysis and observation only

**Methodology:** URL structure analysis, endpoint behavioral inference, parameter enumeration

---

## 1. Target Overview

| Property            | Value                                                                                       |
|---------------------|---------------------------------------------------------------------------------------------|
| Base Domain         | `bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com`                                 |
| Infrastructure      | Kubernetes-deployed (`k8s.tools-001`), Braze dev environment (`braze-dev.com`)              |
| Endpoint Path       | `/app_settings/app_settings/69c8d257629242005dba8746`                                       |
| Known Parameters    | `locale=en`                                                                                 |
| App Identifier      | `69c8d257629242005dba8746` (MongoDB-style ObjectId — 24-char hex)                           |
| Apparent Function   | Application settings / configuration page for a specific app instance                       |

---

## 2. SSRF Attack Surface — Parameter-Level Analysis

Application settings pages commonly expose functionality where users configure external endpoints, URLs, or resources that the backend subsequently fetches or contacts. Below is a systematic analysis of high-risk parameter categories typically found in this type of endpoint.

### 2.1 Webhook Configuration Parameters

| Item          | Detail                                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------------------|
| **Endpoint**  | `/app_settings/app_settings/{app_id}` (POST/PUT/PATCH)                                                                |
| **Parameters**| `webhook_url`, `callback_url`, `notification_url`, `event_url`, `postback_url`                                         |
| **Observation**| App settings pages in marketing/messaging platforms like Braze typically allow users to configure webhook endpoints for event delivery. These webhooks trigger server-side HTTP requests to user-supplied URLs. |
| **Risk Level**| **Likely**                                                                                                             |
| **Reasoning** | Braze's core product involves sending HTTP callbacks to customer-defined endpoints. An app settings page is the primary location where such URLs are configured. If the backend validates or "pings" the webhook URL upon save, or delivers events to it, the server makes outbound requests to user-controlled destinations. An attacker could supply internal URLs (e.g., `http://169.254.169.254/latest/meta-data/`, `http://localhost:PORT/`, or internal Kubernetes service addresses like `http://service-name.namespace.svc.cluster.local/`) to probe internal infrastructure. |

### 2.2 API Endpoint / Integration URL Parameters

| Item          | Detail                                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------------------|
| **Endpoint**  | `/app_settings/app_settings/{app_id}` (POST/PUT/PATCH)                                                                |
| **Parameters**| `api_url`, `api_endpoint`, `base_url`, `rest_endpoint`, `custom_endpoint`                                              |
| **Observation**| Settings pages frequently allow configuring custom API endpoints for integrations (e.g., custom data endpoints, S3-compatible storage URLs, or partner API base URLs). |
| **Risk Level**| **Possible**                                                                                                           |
| **Reasoning** | If the application allows users to set a custom API base URL and the server subsequently makes requests to that URL (e.g., to verify connectivity or fetch configuration), this constitutes an SSRF vector. The Kubernetes deployment context (`k8s.tools-001`) increases risk because internal service discovery via DNS is available. |

### 2.3 Image / Icon URL Parameters

| Item          | Detail                                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------------------|
| **Endpoint**  | `/app_settings/app_settings/{app_id}` (POST/PUT/PATCH)                                                                |
| **Parameters**| `image_url`, `icon_url`, `logo_url`, `app_icon`, `favicon_url`, `brand_image`                                          |
| **Observation**| App settings often include branding configuration where users provide URLs to app icons or logos. Servers commonly fetch these images server-side (for resizing, caching, validation, or proxy serving). |
| **Risk Level**| **Likely**                                                                                                             |
| **Reasoning** | Server-side image fetching is one of the most common SSRF vectors. If the application downloads the image from the user-supplied URL (e.g., to generate thumbnails, validate dimensions, or store in a CDN), it will make an HTTP request to whatever URL is provided. The fetched response may also leak information through error messages or timing differences. |

### 2.4 Redirect / OAuth URL Parameters

| Item          | Detail                                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------------------|
| **Endpoint**  | `/app_settings/app_settings/{app_id}` (POST/PUT/PATCH)                                                                |
| **Parameters**| `redirect_url`, `redirect_uri`, `oauth_callback`, `return_url`, `login_redirect`                                       |
| **Observation**| App settings may include OAuth or SSO configuration where redirect URIs are specified. While these are typically client-side redirects, some implementations perform server-side validation by requesting the URL. |
| **Risk Level**| **Possible**                                                                                                           |
| **Reasoning** | If the backend fetches the redirect URL for validation (e.g., checking for a verification file at the domain), this becomes an SSRF vector. Risk is lower than webhooks/images because redirect URLs are typically used in client-side 302 responses rather than server-side fetches. |

### 2.5 Data Import / Feed URL Parameters

| Item          | Detail                                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------------------|
| **Endpoint**  | `/app_settings/app_settings/{app_id}` (POST/PUT/PATCH)                                                                |
| **Parameters**| `feed_url`, `import_url`, `data_url`, `csv_url`, `rss_url`, `catalog_url`                                              |
| **Observation**| Marketing platforms often support data feeds or catalog imports from external URLs. These are fetched server-side on a schedule or on-demand. |
| **Risk Level**| **Likely**                                                                                                             |
| **Reasoning** | Data import endpoints require the server to fetch content from user-provided URLs, making them inherently SSRF-prone. The import process may also follow redirects and handle various content types, expanding the attack surface. |

### 2.6 Connected Content / Template URL Parameters

| Item          | Detail                                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------------------|
| **Endpoint**  | `/app_settings/app_settings/{app_id}` or related messaging/template endpoints                                          |
| **Parameters**| `connected_content_url`, `template_url`, `content_url`, `dynamic_content_url`                                          |
| **Observation**| Braze specifically supports a "Connected Content" feature that fetches data from external APIs at message send time. If this is configurable at the app settings level, it represents a direct SSRF vector. |
| **Risk Level**| **Likely**                                                                                                             |
| **Reasoning** | Connected Content is a documented Braze feature where the platform makes server-side HTTP requests to user-specified URLs to pull dynamic content into messages. This is by-design server-side URL fetching and a primary SSRF risk surface. Proper allowlisting and egress controls are critical. |

---

## 3. Kubernetes-Specific SSRF Risks

The target is deployed on Kubernetes (`k8s.tools-001`), which introduces additional internal targets:

| Internal Target                                      | Risk                                                              |
|------------------------------------------------------|-------------------------------------------------------------------|
| `http://169.254.169.254/latest/meta-data/`           | AWS Instance Metadata Service — can leak IAM credentials          |
| `http://169.254.169.254/latest/api/token` (IMDSv2)   | Token endpoint for metadata service                               |
| `http://metadata.google.internal/`                   | GCP metadata endpoint (if running on GCP)                         |
| `http://<service>.default.svc.cluster.local`         | Internal Kubernetes services via cluster DNS                      |
| `http://kubernetes.default.svc/`                     | Kubernetes API server                                             |
| `http://localhost:<port>/`                            | Loopback services on the same pod                                 |
| `http://10.x.x.x/` (internal RFC1918)               | Internal network services                                         |

These targets are only reachable from within the cluster network. An SSRF vulnerability would bridge the gap between external input and internal access.

---

## 4. Safe Verification Techniques

The following safe, non-exploitative techniques can be used to confirm SSRF behavior during authorized testing:

### 4.1 Controlled Collaborator Domain

1. Set up a controlled HTTP listener (e.g., Burp Collaborator, Interactsh, or a webhook.site endpoint)
2. Submit the collaborator URL in each candidate parameter
3. Observe whether the controlled server receives an HTTP request from the application's infrastructure
4. Record source IP, headers, user-agent, and timing

### 4.2 Differential Behavior Analysis

1. Submit a valid external URL → observe response (success, timing, content)
2. Submit an invalid/unreachable URL → observe response (error message, timing)
3. Submit `http://localhost/` → observe response (different error? timing difference?)
4. Compare behaviors to infer whether the server is making outbound requests

### 4.3 DNS-Based Detection

1. Use a unique subdomain per test: `<unique-id>.your-collaborator-domain.com`
2. Monitor DNS resolution logs
3. DNS resolution alone (without HTTP) confirms the server is resolving user-supplied hostnames

### 4.4 Timing Analysis

1. Submit a URL pointing to a slow-responding server (controlled delay)
2. If the application response time correlates with the external server's delay, the server is fetching synchronously

---

## 5. Summary of Findings

| # | Endpoint                               | Parameter Category        | Risk Level  | Key Reasoning                                                                                       |
|---|----------------------------------------|---------------------------|-------------|-----------------------------------------------------------------------------------------------------|
| 1 | `/app_settings/.../{app_id}` (mutate)  | Webhook URLs              | **Likely**  | Messaging platforms send HTTP callbacks to user-defined endpoints; settings page is primary config   |
| 2 | `/app_settings/.../{app_id}` (mutate)  | API / Integration URLs    | **Possible**| Custom integration endpoints may trigger server-side connectivity checks                             |
| 3 | `/app_settings/.../{app_id}` (mutate)  | Image / Icon URLs         | **Likely**  | Server-side image fetch for validation/resizing is a classic SSRF vector                             |
| 4 | `/app_settings/.../{app_id}` (mutate)  | Redirect / OAuth URLs     | **Possible**| Lower risk; typically client-side, but server-side validation possible                               |
| 5 | `/app_settings/.../{app_id}` (mutate)  | Data Import / Feed URLs   | **Likely**  | Server must fetch user-provided data feed URLs                                                      |
| 6 | `/app_settings/.../{app_id}` (mutate)  | Connected Content URLs    | **Likely**  | Braze Connected Content is documented server-side URL fetching by design                             |

---

## 6. Recommendations for Testing

1. **Enumerate actual form fields:** Inspect the settings page to identify which URL-accepting parameters are actually present in the form/API requests (use browser DevTools or a proxy like Burp Suite to capture the actual POST/PUT payload structure).

2. **Test with collaborator domains:** For each URL field identified, submit a unique collaborator URL and monitor for callbacks.

3. **Check for allowlisting:** Determine if the application restricts URLs to specific domains or schemes. Test with:
   - Internal IPs (`127.0.0.1`, `169.254.169.254`, `10.0.0.1`)
   - Alternative schemes (`file://`, `gopher://`, `dict://`)
   - DNS rebinding payloads
   - URL encoding / parser differential bypasses

4. **Inspect error responses:** Verbose error messages when invalid URLs are submitted may reveal backend HTTP client behavior (library name, error details, response content).

5. **Check for blind vs. reflected SSRF:** Determine whether response content from fetched URLs is reflected back to the user (full SSRF) or only processed server-side (blind SSRF).

---

## 7. Disclaimer

This analysis is performed under authorized bug bounty testing scope. All findings are based on:
- URL structure analysis
- Common architectural patterns for this type of application
- Known characteristics of the Braze platform
- Standard SSRF methodology

No exploitation was attempted. Findings should be validated through safe, controlled testing techniques as described in Section 4.
