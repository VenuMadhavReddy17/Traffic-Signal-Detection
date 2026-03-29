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

## 7. Step-by-Step Burp Suite Testing Guide

Below is a sequential walkthrough for testing SSRF on the target using Burp Suite. Follow each step in order.

---

### Step 1 — Configure Browser Proxy

1. Open Burp Suite (Community or Professional).
2. Go to **Proxy → Proxy settings**.
3. Confirm the proxy listener is running on `127.0.0.1:8080`.
4. In your browser, set the HTTP/HTTPS proxy to `127.0.0.1:8080`.
   - Firefox: Settings → Network Settings → Manual proxy → `127.0.0.1` port `8080` → check "Also use this proxy for HTTPS".
   - Or use the FoxyProxy extension and create a Burp profile.
5. Visit `http://burpsuite` in the browser and download + install the Burp CA certificate so HTTPS interception works without errors.

---

### Step 2 — Add Target to Scope

1. In Burp, go to **Target → Scope settings**.
2. Click **Add** under "Include in scope".
3. Enter the target:

```
Host: bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com
Protocol: HTTPS
Port: 443
```

4. Go to **Proxy → HTTP history** options and check **Show only in-scope items** to reduce noise.

---

### Step 3 — Browse the Settings Page and Capture Traffic

1. In the proxied browser, navigate to:

```
https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com/app_settings/app_settings/69c8d257629242005dba8746?locale=en
```

2. Log in if required.
3. Let the page fully load.
4. In Burp **Proxy → HTTP history**, you will now see all the requests the page made.
5. Look for:
   - The initial `GET` that loaded the page HTML.
   - Any `XHR`/`fetch` API calls (often `GET` or `POST` to `/api/...` or `/app_settings/...` endpoints) that loaded the settings data.
6. Click each request and inspect the **Response** body — this reveals the actual field names the application uses.

---

### Step 4 — Identify URL-Accepting Parameters

1. On the settings page in the browser, look for any input fields that accept URLs — these might be labeled:
   - Webhook URL / Callback URL
   - Icon / Logo / Image URL
   - API Endpoint
   - Connected Content URL
   - Feed / Import URL
   - Redirect URI
2. Also try submitting/saving the form (even without changes) and watch **HTTP history** for the `POST`/`PUT`/`PATCH` request.
3. Click that save request in Burp and examine the **Request** body — note every parameter name and its value.
4. Write down each parameter that contains or accepts a URL. These are your SSRF test candidates.

---

### Step 5 — Start Burp Collaborator

1. Go to **Burp → Burp Collaborator client** (Professional edition).
   - If using Community edition, use https://webhook.site or https://interact.sh instead — open it in a separate (non-proxied) browser tab and copy the unique URL.
2. In Collaborator, click **Copy to clipboard** to get your unique collaborator subdomain, e.g.:

```
abc123xyz.burpcollaborator.net
```

3. Keep the Collaborator window open — you will poll it for interactions later.

---

### Step 6 — Send the Save Request to Repeater

1. In **Proxy → HTTP history**, find the `POST`/`PUT`/`PATCH` request that saves settings (from Step 4).
2. Right-click it → **Send to Repeater**.
3. Switch to the **Repeater** tab. You now have the full request ready to modify and resend.

---

### Step 7 — Test the First URL Parameter

1. In **Repeater**, locate the first URL parameter you identified (e.g., `webhook_url`).
2. Replace its value with your Collaborator URL:

```
webhook_url=http://abc123xyz.burpcollaborator.net/test-webhook
```

3. Click **Send**.
4. Note the response: status code, body, any error messages.
5. Go to the **Collaborator** tab and click **Poll now**.
6. Check if any DNS or HTTP interaction appeared.

**What to record:**

| Item | Value |
|------|-------|
| Parameter tested | `webhook_url` (or whatever the actual name is) |
| Collaborator URL used | `http://abc123xyz.burpcollaborator.net/test-webhook` |
| HTTP response code | e.g., `200`, `400`, `422` |
| Response body notes | e.g., "success", "invalid URL", error message text |
| Collaborator hit? | Yes / No |
| Hit type | DNS only / HTTP GET / HTTP POST |
| Source IP of hit | (from Collaborator details) |
| User-Agent of hit | (from Collaborator details) |

---

### Step 8 — Repeat for Each URL Parameter

1. Go back to **Repeater**.
2. Use a **different** Collaborator subdomain path for each parameter so you can tell which parameter triggered a callback:

```
Parameter: webhook_url  → http://abc123xyz.burpcollaborator.net/ssrf-webhook
Parameter: icon_url     → http://abc123xyz.burpcollaborator.net/ssrf-icon
Parameter: api_url      → http://abc123xyz.burpcollaborator.net/ssrf-api
Parameter: feed_url     → http://abc123xyz.burpcollaborator.net/ssrf-feed
```

3. For each parameter:
   - Replace the value.
   - Click **Send**.
   - **Poll Collaborator** after each send.
   - Record results in the table format above.

---

### Step 9 — Test for Blind SSRF with Timing

For parameters that did NOT trigger a Collaborator hit but returned a slow or different response:

1. In **Repeater**, set the URL parameter to a valid external URL (e.g., `http://example.com`).
2. Click **Send** and note the response time (shown at bottom-right of Repeater).
3. Now set the URL parameter to a non-routable IP that will cause a timeout:

```
http://10.255.255.1/
```

4. Click **Send** and note the response time.
5. If the second request takes significantly longer (e.g., 5-30 seconds vs. < 1 second), the server is attempting to connect to the URL you provided — this confirms server-side fetching even without a Collaborator callback.

---

### Step 10 — Test Response Reflection (Full vs. Blind SSRF)

For parameters that DID trigger a Collaborator hit:

1. Set up a simple response on your collaborator or use a URL that returns known content (e.g., `http://abc123xyz.burpcollaborator.net` which returns a default page).
2. Submit it in the parameter.
3. Check:
   - Does the application response contain any content fetched from your URL?
   - Does the page display an image preview, a status message, or fetched data?
4. If **yes** → this is a **full (reflected) SSRF** — the server returns the fetched content to you.
5. If **no** → this is a **blind SSRF** — the server fetches the URL but does not return the content.

---

### Step 11 — Check for URL Validation / Allowlisting

For each confirmed SSRF parameter, test what the application blocks:

1. **Localhost:**

```
http://127.0.0.1/
http://localhost/
http://[::1]/
```

2. **Cloud metadata (AWS):**

```
http://169.254.169.254/latest/meta-data/
```

3. **Alternative representations:**

```
http://2130706433/              (decimal IP for 127.0.0.1)
http://0x7f000001/              (hex IP for 127.0.0.1)
http://017700000001/            (octal IP for 127.0.0.1)
http://127.1/                   (short form)
http://0/                       (resolves to 0.0.0.0)
```

4. **DNS rebinding (if you have a controlled domain):**

```
http://your-rebind-domain.com/  (resolves to internal IP after first lookup)
```

5. For each test, record whether the application:
   - Accepts it (potential bypass)
   - Rejects it with an error (note the error message — it reveals validation logic)
   - Times out (server attempted the connection but it failed at network level)

---

### Step 12 — Use Intruder for Automated Parameter Scanning (Optional)

If the settings form has many parameters and you want to test them all efficiently:

1. In **Repeater**, right-click the request → **Send to Intruder**.
2. Go to **Intruder → Positions**.
3. Click **Clear §** to clear all markers.
4. Highlight just the value of one URL parameter and click **Add §**.
5. Go to **Intruder → Payloads**.
6. Set payload type to **Simple list**.
7. Add your Collaborator URLs and internal test URLs as payloads:

```
http://abc123xyz.burpcollaborator.net/intruder-test-1
http://127.0.0.1/
http://169.254.169.254/latest/meta-data/
http://10.255.255.1/
http://kubernetes.default.svc/
```

8. Click **Start attack**.
9. After the attack finishes, review response codes, lengths, and times for anomalies.
10. Poll Collaborator for any hits.

---

### Step 13 — Document Findings

For each confirmed SSRF interaction, document using this template:

```
Endpoint:    POST /app_settings/app_settings/69c8d257629242005dba8746
Parameter:   [actual parameter name]
Observation: Server made an HTTP [GET/POST] request to the Collaborator
             URL within [X] seconds of form submission.
             Source IP: [IP from Collaborator].
             User-Agent: [UA string from Collaborator].
Risk Level:  Confirmed
Reasoning:   The server-side application fetches the URL supplied in
             the [parameter] field. This was verified by observing
             an out-of-band HTTP interaction on a controlled domain.
```

---

### Quick Reference — Order of Operations

```
 1. Proxy setup          → Browser talks through Burp
 2. Scope the target     → Filter noise
 3. Browse & capture     → See real requests
 4. Find URL params      → Identify test candidates
 5. Start Collaborator   → Prepare OOB listener
 6. Send to Repeater     → Isolate the save request
 7. Test first param     → Collaborator URL in param, send, poll
 8. Test all params      → Unique path per param
 9. Timing test          → Non-routable IP vs. valid URL
10. Reflection test      → Full SSRF vs. blind SSRF
11. Validation test      → Localhost, metadata, bypasses
12. Intruder (optional)  → Batch testing
13. Document             → Write up findings
```

---

## 8. Endpoint Checklist for SSRF Testing

The base URL for all endpoints below is:

```
https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com
```

The app ID from the original URL is `69c8d257629242005dba8746`. Replace `{app_id}` with that value in each endpoint.

---

### 8.1 App Settings (Primary Target)

These are the most likely SSRF surfaces — the settings page you already have access to.

| # | Method | Endpoint | Parameters to Test | Why |
|---|--------|----------|--------------------|-----|
| 1 | `GET` | `/app_settings/app_settings/{app_id}?locale=en` | Read response body to discover all field names | Reconnaissance — reveals the actual parameter names the form uses |
| 2 | `PUT` / `PATCH` | `/app_settings/app_settings/{app_id}` | `webhook_url`, `callback_url`, `postback_url` | Saving a webhook URL may trigger server-side validation ping |
| 3 | `PUT` / `PATCH` | `/app_settings/app_settings/{app_id}` | `icon_url`, `image_url`, `logo_url`, `app_icon`, `favicon_url` | Image/icon fields — server may fetch for thumbnail/validation |
| 4 | `PUT` / `PATCH` | `/app_settings/app_settings/{app_id}` | `api_url`, `api_endpoint`, `base_url`, `custom_endpoint` | Integration base URLs — server may test connectivity |
| 5 | `PUT` / `PATCH` | `/app_settings/app_settings/{app_id}` | `redirect_url`, `redirect_uri`, `oauth_callback` | Redirect/OAuth config — possible server-side verification |
| 6 | `PUT` / `PATCH` | `/app_settings/app_settings/{app_id}` | `feed_url`, `import_url`, `data_url`, `catalog_url` | Data import URLs — server fetches content from URL |

---

### 8.2 Webhook Management Endpoints

Dashboard applications typically have dedicated webhook CRUD endpoints.

| # | Method | Endpoint | Parameters to Test | Why |
|---|--------|----------|--------------------|-----|
| 7 | `POST` | `/app_settings/{app_id}/webhooks` | `url`, `endpoint`, `target_url` | Creating a new webhook — server may verify the URL on creation |
| 8 | `PUT` | `/app_settings/{app_id}/webhooks/{webhook_id}` | `url`, `endpoint`, `target_url` | Updating a webhook URL |
| 9 | `POST` | `/app_settings/{app_id}/webhooks/{webhook_id}/test` | (uses stored URL) | "Test webhook" button — sends a live request to the stored URL |
| 10 | `POST` | `/app_settings/{app_id}/webhooks/test` | `url`, `target_url` | Ad-hoc webhook test before saving |

---

### 8.3 Integration / Connected App Endpoints

| # | Method | Endpoint | Parameters to Test | Why |
|---|--------|----------|--------------------|-----|
| 11 | `POST` | `/app_settings/{app_id}/integrations` | `endpoint`, `base_url`, `api_url` | Adding a new third-party integration |
| 12 | `PUT` | `/app_settings/{app_id}/integrations/{integration_id}` | `endpoint`, `base_url`, `api_url` | Updating an integration endpoint |
| 13 | `POST` | `/app_settings/{app_id}/integrations/{integration_id}/test` | (uses stored URL) | "Test connection" — server makes request to the configured endpoint |

---

### 8.4 Connected Content / Dynamic Content Endpoints

Braze's Connected Content feature makes server-side HTTP requests by design.

| # | Method | Endpoint | Parameters to Test | Why |
|---|--------|----------|--------------------|-----|
| 14 | `POST` | `/app_settings/{app_id}/connected_content` | `url`, `content_url`, `api_endpoint` | Configuring a Connected Content source |
| 15 | `POST` | `/app_settings/{app_id}/connected_content/test` | `url` | Testing a Connected Content URL — server fetches it immediately |
| 16 | `POST` | `/app_settings/{app_id}/connected_content/preview` | `url` | Previewing content from an external URL |

---

### 8.5 Data Import / Export Endpoints

| # | Method | Endpoint | Parameters to Test | Why |
|---|--------|----------|--------------------|-----|
| 17 | `POST` | `/app_settings/{app_id}/data_import` | `source_url`, `feed_url`, `csv_url`, `file_url` | Importing data from an external URL |
| 18 | `POST` | `/app_settings/{app_id}/catalogs` | `feed_url`, `catalog_url`, `source_url` | Product catalog feed import |
| 19 | `POST` | `/app_settings/{app_id}/export` | `destination_url`, `callback_url`, `webhook_url` | Export completion callback URL |

---

### 8.6 Branding / Media Endpoints

| # | Method | Endpoint | Parameters to Test | Why |
|---|--------|----------|--------------------|-----|
| 20 | `POST` | `/app_settings/{app_id}/branding` | `logo_url`, `icon_url`, `image_url`, `banner_url` | Brand assets — server fetches/caches images |
| 21 | `POST` | `/app_settings/{app_id}/media` | `url`, `source_url`, `media_url` | Media library — importing media from URL |
| 22 | `POST` | `/app_settings/{app_id}/media/upload_from_url` | `url`, `source_url` | Direct URL-to-media import — server downloads the file |

---

### 8.7 Push Notification / Email Configuration

| # | Method | Endpoint | Parameters to Test | Why |
|---|--------|----------|--------------------|-----|
| 23 | `PUT` | `/app_settings/{app_id}/push_settings` | `apns_endpoint`, `fcm_endpoint`, `callback_url` | Push provider endpoint configuration |
| 24 | `PUT` | `/app_settings/{app_id}/email_settings` | `tracking_url`, `click_tracking_domain`, `unsubscribe_url`, `custom_footer_url` | Email settings — some may trigger server-side verification |
| 25 | `POST` | `/app_settings/{app_id}/email_settings/verify_domain` | `domain`, `url` | Domain verification — server may fetch a verification file |

---

### 8.8 General API Endpoints

| # | Method | Endpoint | Parameters to Test | Why |
|---|--------|----------|--------------------|-----|
| 26 | `POST` | `/api/v1/proxy` or `/api/proxy` | `url`, `target`, `endpoint` | If a proxy endpoint exists, it is a direct SSRF vector |
| 27 | `POST` | `/api/v1/fetch` or `/api/fetch` | `url`, `uri`, `link` | Generic fetch endpoint |
| 28 | `POST` | `/api/v1/preview` | `url` | URL/link preview functionality |
| 29 | `GET` | `/api/v1/image?url=...` | `url` (query param) | Image proxy — passes URL as query parameter |
| 30 | `GET` | `/api/v1/redirect?url=...` | `url`, `redirect`, `next` (query param) | Open redirect that might be fetched server-side |

---

### 8.9 How to Discover the Real Endpoints

The endpoints above are educated guesses based on common patterns. To find the **actual** endpoints:

**Method A — Passive traffic capture:**
1. Open Burp, proxy the browser, browse every page and feature of the dashboard.
2. In **Proxy → HTTP history**, sort by path.
3. Every unique path is a real endpoint you can test.

**Method B — JavaScript source analysis:**
1. In browser DevTools, go to **Sources** (or **Network** → filter by JS).
2. Search the JavaScript bundles for strings like `fetch(`, `axios`, `/api/`, `webhook`, `url`, `endpoint`.
3. These reveal the actual API routes the frontend calls.

**Method C — Sitemap in Burp:**
1. After browsing the app, go to **Target → Site map**.
2. Expand the target host tree.
3. This shows every path Burp has observed, organized hierarchically.

**Method D — Check for API documentation:**
1. Try these common paths for exposed API docs:
   - `/api/docs`
   - `/api/v1/docs`
   - `/swagger`
   - `/swagger-ui`
   - `/swagger.json`
   - `/openapi.json`
   - `/api-docs`
   - `/graphql` (GraphQL Playground)
   - `/graphiql`

---

## 9. Live Testing Findings — Confirmed Intercepted Requests

This section documents real requests captured during authorized testing via Burp Suite.

---

### Finding #1 — Webhook Template Creation (`webhook_url` parameter)

**Intercepted Request:**

```
POST /engagement/webhook_templates/undefined?app_group_id=69c8d257629242005dba8746 HTTP/1.1
Host: bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com
Content-Type: application/json
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

**Analysis:**

| Item | Detail |
|------|--------|
| **Endpoint** | `POST /engagement/webhook_templates/undefined?app_group_id=69c8d257629242005dba8746` |
| **Parameter** | `webhook_url` |
| **Value Sent** | `if1x3ugusgdcn659n48okn054wanyem3.oastify.com` (Burp Collaborator / OAST domain) |
| **Risk Level** | **Possible** — awaiting Collaborator results (see next steps below) |

**Key Observations from the Request:**

1. **`/undefined` in the path** — The URL path contains `/undefined`, which means the frontend JavaScript is passing an undefined template ID. This is a **new template creation** flow (not editing an existing one). The backend likely ignores or replaces the `undefined` segment.

2. **`webhook_url` accepts arbitrary domains** — The application accepted `if1x3ugusgdcn659n48okn054wanyem3.oastify.com` in the `webhook_url` field without immediately rejecting it as invalid. This is notable because:
   - There is no `http://` or `https://` scheme prefix — check if the server auto-prepends a scheme.
   - The domain is clearly not a well-known service — no allowlist is enforced at the form submission level.

3. **`webhook_method: POST`** — The template specifies that the webhook should use HTTP POST. If the server ever sends a test or live webhook, it will make a `POST` request to the Collaborator URL.

4. **`webhook_body: "{}"`** — The webhook body is set to empty JSON. When the webhook fires, the server will send this body to the target URL.

5. **`webhook_headers: {}`** — No custom headers. The server's default headers will be included in any outbound request, potentially leaking internal information (User-Agent, internal tokens, etc.).

---

### Next Steps for This Finding

**Step A — Check Burp Collaborator for interactions:**

1. Go to **Burp → Collaborator** tab.
2. Click **Poll now**.
3. Look for any DNS or HTTP interactions from the `oastify.com` subdomain.
4. **If you see a hit:** Record the details below.
5. **If no hit yet:** The webhook template was only *saved*, not *triggered*. Proceed to Step B.

**Step B — Trigger the webhook to fire:**

The template has been created but may not have been executed yet. Try these actions to trigger it:

1. **Look for a "Test" or "Send Test" button** on the webhook template page in the UI. This would trigger the server to make an HTTP request to `webhook_url` immediately.

2. **Try sending a test request directly** — look in Burp HTTP history for an endpoint like:

```
POST /engagement/webhook_templates/{template_id}/test?app_group_id=69c8d257629242005dba8746
```

or:

```
POST /engagement/webhook_templates/{template_id}/send_test?app_group_id=69c8d257629242005dba8746
```

3. **Check if the template got an ID** — The response to your POST should contain the created template's ID. Find that response in HTTP history and note the `id` field. You'll need it for the test endpoint.

**Step C — Fix the URL scheme:**

Your Collaborator URL is missing the `http://` prefix. Resend the request in Repeater with the corrected URL to ensure the server can actually reach it:

```json
"webhook_url": "https://if1x3ugusgdcn659n48okn054wanyem3.oastify.com"
```

**Step D — Additional parameters to test in this same request:**

The webhook template endpoint accepts several fields. Try injecting Collaborator URLs into these as well (one at a time, using Repeater):

| Test | Modified Field | Payload |
|------|---------------|---------|
| D1 | `webhook_url` | `https://YOUR-ID.oastify.com/ssrf-webhook-url` |
| D2 | `webhook_body` | `https://YOUR-ID.oastify.com/ssrf-webhook-body` |
| D3 | `api_identifier` | `https://YOUR-ID.oastify.com/ssrf-api-id` |
| D4 | `description` | `https://YOUR-ID.oastify.com/ssrf-description` |
| D5 | `webhook_headers` | `{"Host": "YOUR-ID.oastify.com"}` |

---

### Related Endpoints Discovered from This Request

The intercepted request reveals the actual URL structure the application uses. Based on this, here are the real endpoints to explore:

| # | Method | Endpoint | Action |
|---|--------|----------|--------|
| 1 | `GET` | `/engagement/webhook_templates?app_group_id={app_id}` | List all webhook templates |
| 2 | `POST` | `/engagement/webhook_templates?app_group_id={app_id}` | Create a new webhook template (confirmed) |
| 3 | `GET` | `/engagement/webhook_templates/{template_id}?app_group_id={app_id}` | Read a specific template |
| 4 | `PUT` | `/engagement/webhook_templates/{template_id}?app_group_id={app_id}` | Update a template |
| 5 | `DELETE` | `/engagement/webhook_templates/{template_id}?app_group_id={app_id}` | Delete a template |
| 6 | `POST` | `/engagement/webhook_templates/{template_id}/test?app_group_id={app_id}` | **Test/trigger** a template (likely fires the webhook) |
| 7 | `POST` | `/engagement/webhook_templates/{template_id}/send_test?app_group_id={app_id}` | Alternative test endpoint |
| 8 | `POST` | `/engagement/webhook_templates/{template_id}/preview?app_group_id={app_id}` | Preview the webhook request |

Also explore related engagement endpoints:

| # | Method | Endpoint | Action |
|---|--------|----------|--------|
| 9 | `POST` | `/engagement/campaigns?app_group_id={app_id}` | Create a campaign (may reference webhook templates) |
| 10 | `POST` | `/engagement/canvases?app_group_id={app_id}` | Create a Canvas (may reference webhook templates) |
| 11 | `GET` | `/engagement/templates_and_media?app_group_id={app_id}` | List all templates/media |
| 12 | `POST` | `/engagement/email_templates?app_group_id={app_id}` | Email templates (may have URL fields) |
| 13 | `POST` | `/engagement/content_blocks?app_group_id={app_id}` | Content blocks (may have Connected Content URLs) |

---

### Collaborator Result Recording Template

Fill this in once you check Collaborator:

```
Collaborator Domain:  if1x3ugusgdcn659n48okn054wanyem3.oastify.com
Interaction Type:     [ ] DNS only  [ ] HTTP  [ ] None yet
HTTP Method:          _______________
Source IP:            _______________
User-Agent:          _______________
Request Headers:     _______________
Timestamp:           _______________
Latency (from send): _______________

Conclusion:
  [ ] No interaction — webhook was saved but not triggered
  [ ] DNS only — server resolved the domain (confirms SSRF)
  [ ] HTTP hit — server made a full HTTP request (confirms SSRF)
```

---

## 10. Disclaimer

This analysis is performed under authorized bug bounty testing scope. All findings are based on:
- URL structure analysis
- Common architectural patterns for this type of application
- Known characteristics of the Braze platform
- Standard SSRF methodology

No exploitation was attempted. Findings should be validated through safe, controlled testing techniques as described in Section 4.
