# Bug Report: Confirmed SSRF with Full Response Readback via Webhook Templates

## Title
**Server-Side Request Forgery (SSRF) with Full Response Readback in Webhook Template / Campaign Test Send**

## Severity
**High**

## Endpoint
`POST /engagement/webhook_templates/{id}?app_group_id={id}`
Triggered via: Campaign > Webhook > Send Test (dashboard UI)

## Summary
The Braze dashboard webhook feature allows authenticated users to configure arbitrary URLs that are fetched server-side when a webhook test send is triggered. The server makes the HTTP request and **returns the full response body to the user**, enabling full SSRF with response readback. While a blocklist prevents direct access to common internal IP ranges (e.g., `169.254.169.254`, `127.0.0.1`), the vulnerability allows:

1. Making HTTP requests from Braze's internal infrastructure to any external URL
2. Reading the complete HTTP response (status code + body)
3. Full control over the outbound request: URL, HTTP method, body, and headers
4. No input validation at template save time — all URLs including internal IPs are stored
5. The blocklist only applies at send time and does not follow redirects (limiting redirect-based bypass)

## Steps to Reproduce

### Step 1: Create a Webhook Template with Collaborator URL
1. Log in to `https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com`
2. Navigate to **Templates & Media > Webhook Templates > Create New**
3. Set:
   - **Name**: `ssrf-test`
   - **Webhook URL**: `https://YOUR_BURP_COLLABORATOR.oastify.com`
   - **HTTP Method**: POST
4. Click **Save**

**Observation**: Template saves successfully (HTTP 200).

### Step 2: Trigger the Webhook
1. Go to **Campaigns > Create Campaign > Webhook**
2. Use the saved template OR directly set the Webhook URL to your Collaborator domain
3. Go to the **Test** tab
4. Click **Send Test**

**Observation**: 
- Burp Collaborator receives DNS lookup + HTTP request from Braze's server
- Dashboard shows **"Webhook Response"** dialog with:
  - **Message**: `200 OK`
  - **Raw Response**: Full HTML body from the target URL

### Step 3: Demonstrate No Input Validation at Save Time
Create webhook templates with the following URLs — all save successfully (HTTP 200):

| URL | Purpose |
|-----|---------|
| `http://127.0.0.1` | Localhost |
| `http://169.254.169.254/latest/meta-data/` | AWS metadata |
| `http://169.254.169.254/latest/api/token` | AWS IMDSv2 |
| `https://kubernetes.default.svc:443/api/v1/namespaces` | K8s API |
| `http://[::1]` | IPv6 localhost |
| `http://0x7f000001` | Hex-encoded localhost |
| `http://metadata.google.internal/computeMetadata/v1/` | GCP metadata |

All 15+ payloads tested return HTTP 200 `"Save completed."` — zero validation.

### Step 4: Demonstrate Full Response Readback
1. Set **Webhook URL** to `http://YOUR_INTERACTSH_DOMAIN.oast.me`
2. Send Test

**Webhook Response dialog shows:**
```
Message: 200 OK
Raw Response: <html><head></head><body>INTERACTION_ID</body></html>
```

The complete HTTP response body is returned to the user.

### Step 5: Demonstrate Header Injection
1. Create a webhook template with:
   - **Webhook URL**: `https://your-server.com`
   - **Headers**: `X-aws-ec2-metadata-token-ttl-seconds: 21600`
   - **Method**: PUT
2. Save — HTTP 200, headers stored

The user controls all headers in the outbound request. This would enable IMDSv2 token retrieval if the metadata endpoint were reachable.

## Evidence

### Screenshot 1: Full Response Readback (SSRF Confirmed)
Webhook Response dialog showing:
- **Message**: `200 OK`
- **Raw Response**: `<html><head></head><body>ucfokeskyyh1agn2nisvcfdevg1ese47d</body></html>`

This proves the server fetched the URL and returned the response to the user.

### Screenshot 2: TLS Error Disclosure
When targeting an HTTPS interactsh domain:
- **Raw Response**: `tls: failed to verify certificate: x509: certificate is valid for *.oast.me, not bypass-check.d74ese1gvedfcvsin2nga1hyyksekofcu.oast.me`

This reveals server-side TLS implementation details.

### Automated Testing Evidence
- 15/15 SSRF payloads saved without validation (HTTP 200)
- 29/29 bypass payloads saved without validation (HTTP 200)
- Template creation returns full template object including `api_identifier` for API-based triggering

## Impact

### Confirmed Impact
1. **External SSRF with Response**: The server can be used as a proxy to reach any external URL, with the full response returned to the attacker. This enables:
   - Port scanning of external hosts
   - Accessing resources that trust Braze's IP range
   - Exfiltrating data through server-side requests
   - Fingerprinting internal infrastructure via error messages

2. **No Input Validation**: Internal/metadata URLs are stored without any validation. If the send-time blocklist has a bypass (e.g., future DNS rebinding, TOCTOU race condition, or new encoding method), all stored payloads become immediately exploitable.

3. **Full Request Control**: Attacker controls URL, method (GET/POST/PUT), body, and headers. The `webhook_headers` field accepts arbitrary headers including:
   - `X-aws-ec2-metadata-token-ttl-seconds` (IMDSv2 bypass)
   - `Metadata-Flavor: Google` (GCP metadata)
   - `Host` (virtual host routing)
   - `Authorization` (auth header injection)

4. **Information Disclosure**: TLS errors reveal internal certificate details and server-side HTTP client implementation.

### Potential Impact (if blocklist is bypassed)
- AWS IAM credential theft via IMDS
- Kubernetes secret exfiltration
- Internal service access from Braze's network
- Cloud infrastructure compromise

## Blocklist Analysis

The application has a send-time blocklist that prevents requests to:
- `169.254.169.254` (and likely the entire link-local range)
- `127.0.0.1` / `localhost`
- Private IP ranges (`10.x`, `172.16.x`, `192.168.x`)

The blocklist **does NOT** apply at save time. The blocklist appears to resolve DNS and check the IP before connecting. The server does NOT follow HTTP redirects (302).

Bypass attempts tested:
- Decimal IP encoding (`2852039166`) — blocked
- Hex IP encoding (`0xa9fea9fe`) — blocked  
- Octal IP encoding (`0251.0376.0251.0376`) — blocked
- IPv6 mapped (`[::ffff:169.254.169.254]`) — blocked
- DNS wildcards (`169.254.169.254.nip.io`) — blocked
- URL `@` confusion — blocked
- HTTP 302 redirects — not followed

## Remediation Recommendations

1. **Validate URLs at save time**: Reject internal IPs, metadata endpoints, and private ranges when the template is created, not just at send time.
2. **Implement allowlist**: Restrict webhook URLs to known-good domains or require HTTPS with valid certificates.
3. **Restrict headers**: Do not allow users to set arbitrary headers like `X-aws-ec2-metadata-token-ttl-seconds`.
4. **Disable response readback**: Do not return the full HTTP response body to the user — only return success/failure status.
5. **Add DNS pinning**: Resolve DNS once and pin the IP for the duration of the request to prevent TOCTOU race conditions.
6. **Follow principle of least privilege**: The webhook sending service should run with minimal network access and no access to cloud metadata services.

## Environment
- **URL**: `https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com`
- **Infrastructure**: Kubernetes (`k8s.tools-001.d-use-1.braze-dev.com`)
- **App Group ID**: `69c8d257629242005dba8746`
- **Account**: `venu17+3ytlztjh@wearehackerone.com`
