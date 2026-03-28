# SSRF Vulnerability Analysis Report — Ory Kratos

**Date:** 2026-03-28  
**Project:** Ory Kratos (Identity Management Service)  
**Path:** `/workspace/ory-repos/kratos/`  
**Language:** Go  
**Analysis Type:** Static Source Code Analysis  

---

## Executive Summary

Ory Kratos has a **well-engineered SSRF mitigation framework** built into its HTTP client infrastructure. The primary defense is a configurable private-IP blocking mechanism (`clients.http.disallow_private_ip_ranges`) that uses the `code.dny.dev/ssrf` library at the transport/dialer level. When enabled, this blocks outbound connections to RFC 1918, loopback, and link-local addresses.

However, the protection is **opt-in (disabled by default)**, and there are several attack surfaces where admin-controlled or configuration-controlled URLs flow into backend HTTP requests. A few specific patterns present higher risk depending on deployment context.

---

## SSRF Mitigation Infrastructure

### 1. Transport-Level SSRF Protection (Core Defense)

**File:** `oryx/httpx/ssrf.go` (lines 1–134)

The primary SSRF defense operates at the `net.Dialer.Control` level using the `code.dny.dev/ssrf` library. Two transport variants are initialized:

- `prohibitInternalAllowIPv6` — blocks connections to private/loopback/link-local IPs
- `allowInternalAllowIPv6` — allows all connections (including internal IPs)

These are used by `noInternalIPRoundTripper` which selects the appropriate transport based on a glob-matched exception list.

**Strengths:**
- Protection at the TCP dial level means DNS rebinding attacks are mitigated (IP is checked at connect time, not just at URL parse time).
- Covers all HTTP methods (GET, POST, etc.) uniformly.
- Exception URLs use glob matching for flexibility.

**Weaknesses/Notes:**
- The code itself notes the TOCTOU concern for DNS: "A malicious actor could easily update the DNS record post validation to point to an internal IP" (`oryx/httpx/private_ip_validator.go`, line 25). However, the transport-level `ssrf.Safe` dialer in `ssrf.go` mitigates this since it checks at dial time.

### 2. Global HTTP Client with Configurable IP Blocking

**File:** `driver/registry_default.go` (lines 784–801)

```go
func (m *RegistryDefault) HTTPClient(_ context.Context, opts ...httpx.ResilientOptions) *retryablehttp.Client {
    // ...
    if m.Config().ClientHTTPNoPrivateIPRanges(contextx.RootContext) {
        opts = append(opts,
            httpx.ResilientClientDisallowInternalIPs(),
            httpx.ResilientClientAllowInternalIPRequestsTo(m.Config().ClientHTTPPrivateIPExceptionURLs(contextx.RootContext)...),
        )
    }
    return httpx.NewResilientClient(opts...)
}
```

**Configuration keys:**
- `clients.http.disallow_private_ip_ranges` (boolean, **default: false**)
- `clients.http.private_ip_exception_urls` (string array of glob patterns)

**Risk:** The SSRF protection is **disabled by default**. Deployments that do not explicitly set `disallow_private_ip_ranges: true` have no transport-level SSRF protection on outbound HTTP requests.

### 3. Redirect URL Allowlisting

**File:** `x/redir/secure_redirect.go` (lines 105–149)

Self-service flow redirects use an allowlist mechanism that checks scheme, host (with wildcard support), and path prefix. This prevents open-redirect attacks but is not an SSRF concern since the redirect URL is returned to the user's browser, not fetched server-side.

---

## Findings by Attack Surface

---

### Finding 1: Webhook URL — Admin-Configured, Server-Side Fetch

**Files:**
- `selfservice/hook/web_hook.go` (lines 302–440)
- `request/builder.go` (lines 72–111)
- `request/config.go` (lines 19–33)

**Endpoint/Function:** `WebHook.execute()` → `request.NewBuilder()` → `httpClient.Do(req)`

**Parameter:** `Config.URL` field — configured via `selfservice.flows.*.hooks[].config.url` in Kratos configuration.

**Observation:**  
The webhook URL is taken from `request.Config.URL` (set via admin configuration/API) and used directly to construct an HTTP request at line 86 of `request/builder.go`:
```go
r, err := retryablehttp.NewRequest(c.Method, c.URL, nil)
```
The request is then executed via `httpClient.Do(req)` (line 390 of `web_hook.go`). The HTTP client used is the global `deps.HTTPClient(ctx)` which respects `disallow_private_ip_ranges` when configured.

**Risk Level:** Possible  
**Reasoning:** The webhook URL is admin-configured, not user-controllable in standard flows. However, in multi-tenant or delegated-admin scenarios, an admin could set a webhook URL pointing to internal services (cloud metadata endpoints, internal APIs). SSRF protection depends on `disallow_private_ip_ranges` being enabled. The webhook body can contain user data (identity, flow data), which could leak sensitive info to attacker-controlled endpoints.

---

### Finding 2: Webhook/Request TemplateURI — Jsonnet Template Fetching

**Files:**
- `request/builder.go` (lines 283–307)
- `oryx/fetcher/fetcher.go` (lines 87–157)

**Endpoint/Function:** `Builder.readTemplate()` → `fetcher.FetchContext()` → `fetchRemote()`

**Parameter:** `Config.TemplateURI` (configured as `body` in webhook config JSON)

**Observation:**  
The Jsonnet template URI is fetched via the `Fetcher` which supports `http://`, `https://`, `file://`, and `base64://` schemes. When the scheme is `http(s)://`, it makes an outbound HTTP GET request:
```go
req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, source, nil)
res, err := f.hc.Do(req)
```
The HTTP client is the global `deps.HTTPClient(ctx)`, so SSRF protection applies when enabled. The fetcher has caching, so after the first fetch, subsequent requests use cache.

**Risk Level:** Possible  
**Reasoning:** The template URI is admin-configured. If an admin sets it to an internal URL, the server will fetch it. The `file://` scheme also allows reading local files. Since this is configuration-driven (not user input), the risk is limited to admin-level SSRF. When `disallow_private_ip_ranges` is enabled, HTTP fetches to private IPs are blocked, but `file://` reads are not affected by this control.

---

### Finding 3: OIDC Provider IssuerURL — Admin-Configured, Server-Side Discovery

**Files:**
- `selfservice/strategy/oidc/provider_generic_oidc.go` (lines 51–59)
- `selfservice/strategy/oidc/provider_auth0.go` (lines 46–69, 76–125)
- `selfservice/strategy/oidc/provider_config.go` (lines 37–175)

**Endpoint/Function:** `ProviderGenericOIDC.provider()` → `gooidc.NewProvider()`, `Claims()` → `UserInfo()`

**Parameter:** `Configuration.IssuerURL` — configured via `selfservice.methods.oidc.config.providers[].issuer_url`

**Observation:**  
When a generic OIDC provider is configured, the `IssuerURL` is used to perform OpenID Connect Discovery (fetching `/.well-known/openid-configuration`) and subsequently fetching JWKS, token endpoints, and userinfo endpoints. All these are server-side HTTP requests.

For Auth0 provider, the issuer URL is used to construct `{issuer}/authorize`, `{issuer}/oauth/token`, and `{issuer}/userinfo` URLs.

The HTTP client used is `g.reg.HTTPClient(ctx)` (via `gooidc.ClientContext`), which respects SSRF protections when enabled.

**Risk Level:** Possible  
**Reasoning:** The issuer URL is admin-configured. Tests in `provider_private_net_test.go` explicitly verify that when `disallow_private_ip_ranges` is true, private IPs in issuer URLs are blocked. Without this config, an admin could point issuer URLs to internal services. The test coverage for this SSRF scenario is good.

---

### Finding 4: OIDC Claims from UserInfo Endpoint

**Files:**
- `selfservice/strategy/oidc/provider_generic_oidc.go` (lines 132–182)
- Various provider files: `provider_auth0.go`, `provider_facebook.go`, `provider_salesforce.go`, `provider_gitlab.go`, etc.

**Endpoint/Function:** `Claims()` methods on each provider

**Parameter:** The userinfo URL is derived from OIDC discovery or constructed from `IssuerURL`.

**Observation:**  
After OAuth2 token exchange, providers fetch user claims either from the ID token (local verification) or from userinfo endpoints (server-side HTTP request). Providers like Auth0, Facebook, Salesforce, GitLab, VK, Yandex, etc., all make outbound HTTP calls to fetch user data.

For generic OIDC providers, the userinfo URL comes from the discovery document (which was fetched from the issuer URL). For specific providers like Facebook, URLs are hardcoded (`https://graph.facebook.com/me`).

All use `g.reg.HTTPClient(ctx)` which respects SSRF controls.

**Risk Level:** Possible (for generic OIDC), Low (for hardcoded providers)  
**Reasoning:** For hardcoded providers (Facebook, Google, etc.), the URLs are fixed and public — no SSRF risk. For the generic OIDC provider, the userinfo URL is derived from the OIDC discovery document at the admin-configured issuer URL. If an attacker controls a malicious OIDC issuer, they could serve a discovery document pointing the userinfo endpoint to an internal IP. However: (a) the admin must configure this issuer, and (b) SSRF protection at the transport level blocks internal IPs when enabled.

---

### Finding 5: OIDC Mapper URL — Jsonnet Snippet Fetching

**File:** `selfservice/strategy/oidc/strategy_registration.go` (lines 390–395)

**Endpoint/Function:** `Strategy.EvaluateClaimsMapper()` → `fetcher.FetchContext()`

**Parameter:** `provider.Config().Mapper` — configured via `selfservice.methods.oidc.config.providers[].mapper_url`

**Observation:**  
The mapper URL (Jsonnet code for mapping OIDC claims to identity traits) supports `http://`, `https://`, `file://`, and `base64://` schemes. When HTTP is used, the server fetches the Jsonnet code from the specified URL.

**Risk Level:** Possible  
**Reasoning:** Admin-configured URL. Same fetcher infrastructure with SSRF protection when enabled. The `file://` scheme allows reading local files which is by design for file-based configurations but could be a concern in shared hosting environments.

---

### Finding 6: Identity Schema Loading from URLs

**File:** `schema/handler.go` (lines 228–265)

**Endpoint/Function:** `Handler.ReadSchema()` — called by `getIdentitySchema` (public API) and `getAll`

**Parameter:** `Schema.URL` — configured via `identity.schemas[].url`

**Observation:**  
Identity schemas can be loaded from `file://`, `base64://`, or any other URL scheme (HTTP/HTTPS). For non-file/non-base64 schemes, the handler makes an HTTP GET request:
```go
req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
resp, err := h.r.HTTPClient(ctx).Do(req)
```
The public API endpoint `/schemas/{id}` triggers this fetch. While the schema URLs are admin-configured, the fetch is triggered by any unauthenticated request to the public schemas endpoint.

**Risk Level:** Possible  
**Reasoning:** An admin configures schema URLs, but any public user can trigger the fetch by requesting `/schemas/{id}`. If an admin configures a schema URL pointing to an internal service, every public request for that schema would cause the server to fetch from that internal URL. SSRF protection via `disallow_private_ip_ranges` mitigates this for private IPs. The schema data is returned to the public caller, making this a potential data exfiltration vector if pointing to internal services.

---

### Finding 7: JSON Schema `$ref` Resolution

**Files:**
- `schema/validator.go` (lines 41–79)
- `driver/config/config.go` (lines 468–478)
- `schema/schema.go` (lines 134–155)

**Endpoint/Function:** `jsonschema.LoadURL()` and `compiler.Compile()` (from `github.com/ory/jsonschema/v3`)

**Parameter:** `$ref` values within JSON schemas

**Observation:**  
JSON schemas support `$ref` references which the JSON schema compiler resolves by loading URLs. The `jsonschema.LoadURL` function is used in multiple places. The config validator at `config.go:457` injects the SSRF-protected client into the context for the HTTP loader:
```go
if p.ClientHTTPNoPrivateIPRanges(ctx) {
    opts = append(opts, httpx.ResilientClientDisallowInternalIPs())
}
ctx = context.WithValue(ctx, httploader.ContextKey, httpx.NewResilientClient(opts...))
```
This means schema `$ref` resolution respects SSRF protection when enabled.

**Risk Level:** Possible  
**Reasoning:** A malicious schema with `$ref` pointing to internal URLs could cause server-side fetches. Test `TestSchemaValidatorDisallowsInternalNetworkRequests` in `identity/validator_test.go` verifies this is blocked when SSRF protection is enabled. Without protection, `$ref` URLs could reach internal services.

---

### Finding 8: Courier Template Remote Loading

**File:** `courier/template/load_template.go` (lines 79–105)

**Endpoint/Function:** `loadRemoteTemplate()` → `fetcher.FetchContext()`

**Parameter:** Various `courier.templates.*.email.{subject,body.html,body.plaintext}` config values

**Observation:**  
Email/SMS templates can be loaded from remote URLs. The template URL is configured via Kratos config (e.g., `courier.templates.recovery.valid.email.subject`). When set, the `loadRemoteTemplate()` function fetches the template:
```go
f := fetcher.NewFetcher(fetcher.WithClient(d.HTTPClient(ctx)))
bb, err := f.FetchContext(ctx, url)
```
Uses `d.HTTPClient(ctx)` which respects SSRF protection when enabled.

**Risk Level:** Possible  
**Reasoning:** Admin-configured URLs. Fetch happens when the courier sends a message (triggered by user actions like registration, recovery). Template content is not returned to the user, reducing data exfiltration risk. SSRF protection applies when enabled.

---

### Finding 9: Courier HTTP Channel — Outbound Message Delivery

**File:** `courier/http_channel.go` (lines 65–133)

**Endpoint/Function:** `httpChannel.Dispatch()` → `request.NewBuilder()` → `httpClient.Do(req)`

**Parameter:** `courier.http.request_config.url` and `courier.channels[].request_config.url`

**Observation:**  
When using HTTP-based courier delivery (instead of SMTP), Kratos sends messages via HTTP POST to a configured URL. The URL is from admin configuration and the request body contains message content (recipient, subject, body, template data).

**Risk Level:** Possible  
**Reasoning:** Admin-configured URL. Could be pointed at internal services. Sends sensitive message content (emails, SMS codes). SSRF protection applies when enabled.

---

### Finding 10: Password Migration Hook

**File:** `selfservice/hook/password_migration_hook.go` (lines 48–139)

**Endpoint/Function:** `PasswordMigration.Execute()` → `httpClient.Do(whReq)`

**Parameter:** `selfservice.methods.password.config.migrate_hook.config.url`

**Observation:**  
The password migration hook sends user credentials (identifier + password) to an external endpoint during login to check legacy password databases. The URL is admin-configured and the request body contains **plaintext passwords**.

**Risk Level:** Possible  
**Reasoning:** Admin-configured URL. Sends plaintext passwords. If pointed at an attacker-controlled or internal service, credentials would be leaked. SSRF protection applies when enabled. The high sensitivity of the data (passwords) makes misconfiguration particularly dangerous.

---

### Finding 11: Session Tokenizer — JWKS URL and Claims Mapper URL

**File:** `session/tokenizer.go` (lines 75–181)

**Endpoint/Function:** `Tokenizer.TokenizeSession()` → `JWKSFetcher().ResolveKey()` and `fetcher.FetchContext()`

**Parameters:**
- `session.whoami.tokenizer.templates.<name>.jwks_url`
- `session.whoami.tokenizer.templates.<name>.claims_mapper_url`

**Observation:**  
The session tokenizer fetches JWK sets from a configured URL to sign JWT tokens, and optionally fetches a Jsonnet claims mapper. Both use `s.r.HTTPClient(ctx)`.

**Risk Level:** Possible  
**Reasoning:** Admin-configured URLs. The JWKS URL is particularly sensitive — if an attacker could make the server fetch from a malicious endpoint, they could potentially influence JWT signing (though the key material validation would likely prevent signing with arbitrary keys). SSRF protection applies when enabled.

---

### Finding 12: Hydra OAuth2 Provider Integration

**File:** `hydra/hydra.go` (lines 66–172)

**Endpoint/Function:** `DefaultHydra.getAdminAPIClient()` → API calls to Hydra

**Parameter:** `oauth2_provider.url`

**Observation:**  
Kratos integrates with Ory Hydra by making HTTP requests to the configured OAuth2 provider URL. The URL is used for accept-login and get-login-request operations. Uses `h.d.HTTPClient(ctx).StandardClient()`.

**Risk Level:** Possible  
**Reasoning:** Admin-configured URL to a trusted service (Hydra). In misconfigured deployments, could reach unintended internal services. SSRF protection applies when enabled.

---

### Finding 13: HaveIBeenPwned API Host — Configurable DNS Name

**File:** `selfservice/strategy/password/validator.go` (lines 119–167)

**Endpoint/Function:** `DefaultPasswordValidator.fetch()` → `s.Client.Do(req)`

**Parameter:** `selfservice.methods.password.config.haveibeenpwned_host` (default: `api.pwnedpasswords.com`)

**Observation:**  
The HIBP host is configurable via config. The validator constructs URLs like `https://{host}/range/{prefix}`. The HTTP client used is created with `httpx.NewResilientClient(httpx.ResilientClientWithConnectionTimeout(time.Second))` — **without** `ResilientClientDisallowInternalIPs()`.

```go
Client: httpx.NewResilientClient(
    httpx.ResilientClientWithConnectionTimeout(time.Second),
),
```

This client does **not** use the global registry's `HTTPClient()` and does **not** inherit the `disallow_private_ip_ranges` setting.

**Risk Level:** Likely  
**Reasoning:** The password validator creates its own HTTP client that bypasses the global SSRF protection. If an admin sets `haveibeenpwned_host` to an internal hostname/IP, the server will connect to it, sending password hash prefixes. This is a higher risk than other findings because: (1) the SSRF mitigation is bypassed, (2) the data sent (password hash prefixes) is sensitive, and (3) the request is triggered by any user during password-based registration or login. However, the parameter is only admin-configurable, not user-controllable.

---

### Finding 14: Reverse Proxy in oryx/proxy Package

**File:** `oryx/proxy/proxy.go` (lines 277–300)

**Endpoint/Function:** `proxy.New()` → `httputil.ReverseProxy{}`

**Parameter:** `HostConfig.UpstreamHost` and `HostConfig.UpstreamScheme` (determined by `HostMapper`)

**Observation:**  
The proxy package creates an `httputil.ReverseProxy` that forwards requests to upstream hosts. The upstream is determined by the `HostMapper` function provided at construction time. The default transport is `http.DefaultTransport` with no SSRF protection.

**Risk Level:** Possible  
**Reasoning:** This is a library/utility package in `oryx/`. Whether it represents an SSRF risk depends on how `HostMapper` is implemented by callers. The proxy itself has no built-in SSRF mitigation. If used in Kratos (or related Ory services) with user-influenced host mapping, it could be an SSRF vector. Within the Kratos codebase itself, this proxy is not directly used in the main application.

---

### Finding 15: `osx.ReadFileFromAllSources` — File and HTTP Fetcher

**File:** `oryx/osx/file.go` (lines 144–221)

**Endpoint/Function:** `ReadFileFromAllSources()` / `readFile()`

**Parameter:** `source` string

**Observation:**  
This utility function reads from `file://`, `http://`, `https://`, and `base64://` schemes. The HTTP client defaults to `httpx.NewResilientClient()` without SSRF protection unless a custom client is injected via `WithHTTPClient()`.

**Risk Level:** Possible  
**Reasoning:** This is a utility function. SSRF risk depends on whether the `source` parameter can be influenced by users and whether callers inject an SSRF-protected client. The default client has no SSRF protection.

---

## Summary Table

| # | Component | File | Parameter Source | Data Sensitivity | SSRF Protection | Risk Level |
|---|-----------|------|-----------------|------------------|-----------------|------------|
| 1 | Webhook URL | `selfservice/hook/web_hook.go` | Admin config | Flow/identity data | Yes (when enabled) | Possible |
| 2 | Webhook Template URI | `request/builder.go` | Admin config | Template content | Yes (when enabled) | Possible |
| 3 | OIDC Issuer URL | `strategy/oidc/provider_generic_oidc.go` | Admin config | OIDC discovery | Yes (when enabled) | Possible |
| 4 | OIDC UserInfo | Various provider files | Derived from issuer | User claims | Yes (when enabled) | Possible |
| 5 | OIDC Mapper URL | `strategy/oidc/strategy_registration.go` | Admin config | Jsonnet code | Yes (when enabled) | Possible |
| 6 | Schema Loading | `schema/handler.go` | Admin config (public trigger) | Schema JSON | Yes (when enabled) | Possible |
| 7 | Schema `$ref` | `schema/validator.go` | Schema content | Referenced schemas | Yes (when enabled) | Possible |
| 8 | Courier Templates | `courier/template/load_template.go` | Admin config | Template content | Yes (when enabled) | Possible |
| 9 | Courier HTTP Channel | `courier/http_channel.go` | Admin config | Message content | Yes (when enabled) | Possible |
| 10 | Password Migration Hook | `selfservice/hook/password_migration_hook.go` | Admin config | **Plaintext passwords** | Yes (when enabled) | Possible |
| 11 | Session Tokenizer | `session/tokenizer.go` | Admin config | JWKS / Jsonnet | Yes (when enabled) | Possible |
| 12 | Hydra Integration | `hydra/hydra.go` | Admin config | OAuth2 data | Yes (when enabled) | Possible |
| **13** | **HIBP Validator** | **`strategy/password/validator.go`** | **Admin config** | **Password hash prefixes** | **NO (bypassed)** | **Likely** |
| 14 | Reverse Proxy | `oryx/proxy/proxy.go` | HostMapper function | Proxied requests | No (default transport) | Possible |
| 15 | File/URL Reader | `oryx/osx/file.go` | Caller-provided | File/URL content | No (default client) | Possible |

---

## Key Architectural Observations

### 1. SSRF Protection is Opt-In
The `clients.http.disallow_private_ip_ranges` config key defaults to `false`. Deployments must explicitly enable it. This is documented but represents a significant security gap for default installations.

### 2. Transport-Level Protection is Strong When Enabled
The `ssrf.Safe` dialer check at connect time is robust against DNS rebinding. The glob-based exception list adds flexibility without compromising security.

### 3. Password Validator Bypasses Global SSRF Protection (Finding 13)
`DefaultPasswordValidator` creates its own `httpx.NewResilientClient` without `ResilientClientDisallowInternalIPs()`. Even when `disallow_private_ip_ranges` is enabled globally, the HIBP client ignores it. This is the most notable gap.

### 4. All Configuration-Driven URLs Share the Same Risk Profile
Almost all SSRF vectors are admin-configured. If the admin is trusted and the configuration channel is secure, the risk is limited to misconfiguration. In multi-tenant deployments where tenant admins control configuration, the risk increases.

### 5. `file://` Scheme Is Intentionally Supported
Multiple components support `file://` URLs for reading local files. This is by design for file-based configurations but could be a local file disclosure risk in shared environments.

### 6. Good Test Coverage for SSRF Scenarios
Tests in `provider_private_net_test.go`, `identity/validator_test.go`, `web_hook_integration_test.go`, and `courier/sms_test.go` explicitly verify SSRF protections, demonstrating security awareness in the development process.

---

## Recommendations

1. **Consider enabling `disallow_private_ip_ranges` by default** — or at minimum, emit a prominent warning at startup when it is disabled.

2. **Fix Finding 13:** The `DefaultPasswordValidator` should use the registry's `HTTPClient()` rather than creating its own unprotected client, so it inherits the global SSRF protection settings.

3. **Audit `file://` scheme support** in fetcher/osx components to ensure path traversal and sensitive file access is appropriately restricted.

4. **Consider rate-limiting or caching schema fetches** triggered by the public `/schemas/{id}` endpoint to prevent abuse as an SSRF oracle.

5. **Document SSRF protection requirements** in deployment guides, especially for cloud/multi-tenant environments where metadata service access (169.254.169.254) is a concern.
