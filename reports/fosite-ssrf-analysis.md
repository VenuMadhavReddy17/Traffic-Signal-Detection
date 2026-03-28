# SSRF Vulnerability Analysis Report — Ory Fosite

**Project:** Ory Fosite (OAuth2/OIDC SDK Library for Go)  
**Scope:** Static source code analysis for Server-Side Request Forgery (SSRF)  
**Date:** 2026-03-28  
**Analyst:** Automated static analysis (Claude)

---

## Executive Summary

Fosite is an **SDK/library** (not a standalone server). It makes **two categories of outbound HTTP requests** based on data that flows from client-registered metadata or user-supplied authorization parameters:

1. **OpenID Connect `request_uri` fetching** — fetches JWT request objects from a URI provided in the authorization request.
2. **JWKS URI fetching** — fetches JSON Web Key Sets from a client's registered `jwks_uri` for signature verification.

Both of these are inherent to the OAuth2/OIDC specification and are SSRF-relevant attack surfaces. The library provides **partial mitigations** (allowlisting for `request_uri`) but **no network-layer SSRF protections** (e.g., blocking private IP ranges, DNS rebinding protections, or scheme restrictions on outbound fetches).

**Total outbound HTTP request sites found in non-test production code: 2**

---

## Finding 1: `request_uri` Fetching in Authorization Endpoint (OIDC JAR)

### Details

| Field | Value |
|-------|-------|
| **File** | `authorize_request_handler.go` |
| **Lines** | 62–84 |
| **Function** | `Fosite.authorizeRequestParametersFromOpenIDConnectRequest()` |
| **Parameter** | `request_uri` (from the authorization request form) |
| **Risk Level** | **Possible** (mitigated by allowlist, but with caveats) |

### Code Flow

```
63:84:authorize_request_handler.go
	if location := request.Form.Get("request_uri"); len(location) > 0 {
		if !stringslice.Has(oidcClient.GetRequestURIs(), location) {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Request URI '%s' is not whitelisted by the OAuth 2.0 Client.", location))
		}

		hc := f.Config.GetHTTPClient(ctx)
		response, err := hc.Get(location)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because: %s.", err.Error()).WithWrap(err).WithDebug(err.Error()))
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because status code '%d' was expected, but got '%d'.", http.StatusOK, response.StatusCode))
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because body parsing failed with: %s.", err).WithWrap(err).WithDebug(err.Error()))
		}

		assertion = string(body)
	}
```

### Observation

The server-side code fetches content from a URL provided in the `request_uri` authorization parameter. Before fetching, it checks whether the URL is in the client's pre-registered `RequestURIs` allowlist (line 64), using exact string matching via `stringslice.Has()`.

### Mitigations Present

1. **Allowlist check**: The `request_uri` value must exactly match one of the URIs registered in `oidcClient.GetRequestURIs()`. This is a strong mitigation against arbitrary SSRF.
2. **JWT signature verification**: After fetching, the response body is parsed as a signed JWT and verified against the client's registered keys (lines 87–126).

### Residual SSRF Risks

1. **Client registration controls the allowlist**: The `RequestURIs` field on `DefaultOpenIDConnectClient` (`client.go:98`) is populated from client registration data. If the application using Fosite allows clients to self-register or update their `request_uris` without validation, an attacker could register an internal URL (e.g., `http://169.254.169.254/latest/meta-data/`, `http://localhost:8080/admin`) as a pre-registered request URI. The library itself performs **no validation on the scheme, host, or network reachability** of the registered `request_uris`.

2. **No network-layer protections**: The HTTP client used (`retryablehttp.Client` from `config_default.go:278-282`) has no built-in protections against:
   - Requests to private/internal IP ranges (RFC 1918: `10.x.x.x`, `172.16.x.x-172.31.x.x`, `192.168.x.x`)
   - Requests to cloud metadata endpoints (`169.254.169.254`)
   - DNS rebinding attacks
   - Non-HTTP(S) schemes (although `retryablehttp` likely limits this)

3. **No response size limit**: `io.ReadAll(response.Body)` (line 79) reads the entire response body with no size limit, potentially allowing denial-of-service through large responses. (Not SSRF per se, but a related concern.)

4. **Configurable HTTP client**: If the integrator supplies a custom `HTTPClient` via `Config.HTTPClient`, the security properties depend entirely on that client's configuration. The default `retryablehttp.NewClient()` has no SSRF mitigations.

### Reasoning

This is a **Possible** risk because the allowlist is a strong control, but the security depends entirely on how the integrating application manages client registration. If clients can register arbitrary URIs, this becomes a confirmed SSRF vector. The library provides no guidance or built-in validation of `request_uris` values during registration.

---

## Finding 2: JWKS URI Fetching for Client Authentication

### Details

| Field | Value |
|-------|-------|
| **File** | `client_authentication_jwks_strategy.go` |
| **Lines** | 97–131 |
| **Function** | `DefaultJWKSFetcherStrategy.Resolve()` |
| **Parameter** | `location` (from `oidcClient.GetJSONWebKeysURI()`, i.e., client's registered `jwks_uri`) |
| **Risk Level** | **Possible** (depends on client registration controls) |

### Code Flow

```
97:127:client_authentication_jwks_strategy.go
func (s *DefaultJWKSFetcherStrategy) Resolve(ctx context.Context, location string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	cacheKey := defaultJWKSFetcherStrategyCachePrefix + location
	key, ok := s.cache.Get(cacheKey)
	if !ok || ignoreCache {
		req, err := retryablehttp.NewRequest("GET", location, nil)
		if err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to create HTTP 'GET' request to fetch  JSON Web Keys from location '%s'.", location).WithWrap(err).WithDebug(err.Error()))
		}

		hc := s.client
		if s.clientSourceFunc != nil {
			hc = s.clientSourceFunc(ctx)
		}

		response, err := hc.Do(req.WithContext(ctx))
		if err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to fetch JSON Web Keys from location '%s'. Check for typos or other network issues.", location).WithWrap(err).WithDebug(err.Error()))
		}
		defer response.Body.Close()

		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Expected successful status code in range of 200 - 399 from location '%s' but received code %d.", location, response.StatusCode))
		}

		var set jose.JSONWebKeySet
		if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to decode JSON Web Keys from location '%s'. Please check for typos and if the URL returns valid JSON.", location).WithWrap(err).WithDebug(err.Error()))
		}

		_ = s.cache.SetWithTTL(cacheKey, &set, 1, s.ttl)
		return &set, nil
	}
	// ...
```

### Call Sites

This `Resolve()` method is called from two code paths:

1. **`client_authentication.go:36-51`** — `findClientPublicJWK()`: Called during `private_key_jwt` client authentication at the **token endpoint** and during **request object** signature verification at the **authorization endpoint**. The `location` comes from `oidcClient.GetJSONWebKeysURI()`.

2. **`authorize_request_handler.go:103`** (indirectly via `findClientPublicJWK`) — When verifying the signature of a request object (JAR), if the client has a `jwks_uri` registered instead of inline `jwks`.

### Observation

The `Resolve()` function performs an HTTP GET to whatever URL is stored in the client's `jwks_uri` field. There is **no validation** of the URL before the request is made — no scheme check, no host/IP validation, no private network blocking.

### Mitigations Present

1. **Client-registered data**: The `jwks_uri` is a property of the registered client (`DefaultOpenIDConnectClient.JSONWebKeysURI`), not a user-supplied request parameter. This means the URI was set at client registration time, not at request time.
2. **Caching**: Results are cached (with a default 1-hour TTL), reducing the frequency of outbound requests per URI.
3. **Configurable HTTP client**: Integrators can supply a custom `retryablehttp.Client` with SSRF protections via `JWKSFetcherWithHTTPClient()` or `JWKSFetcherWithHTTPClientSource()`.

### Residual SSRF Risks

1. **Same as Finding 1**: If the application allows clients to register or update their `jwks_uri` without validation, an attacker could point it to internal services. The library performs **no validation** of the `jwks_uri` value.

2. **Triggered by normal authentication flow**: Unlike `request_uri` which is only used in OIDC flows, `jwks_uri` fetching is triggered during normal `private_key_jwt` client authentication at the token endpoint. This means any authenticated client request can trigger a server-side fetch.

3. **Double fetch on cache miss**: The code in `findClientPublicJWK()` (lines 37-51 of `client_authentication.go`) first calls `Resolve(ctx, location, false)` (using cache) and if the key is not found, calls `Resolve(ctx, location, true)` (bypassing cache). A crafty attacker could cause repeated cache bypasses by using a valid `jwks_uri` but rotating keys.

4. **No network-layer protections**: Same as Finding 1 — no private IP blocking, no DNS rebinding protection, no scheme restrictions beyond what `retryablehttp` enforces.

### Reasoning

This is a **Possible** risk because the `jwks_uri` comes from client registration data (not from request parameters), but if client registration is not properly controlled, it is a direct SSRF vector. The library provides **no built-in validation** of `jwks_uri` values.

---

## Finding 3: HTTP Client Configuration Without Default SSRF Protections

### Details

| Field | Value |
|-------|-------|
| **File** | `config_default.go` |
| **Lines** | 278–283 |
| **Function** | `Config.GetHTTPClient()` |
| **Parameter** | N/A (configuration) |
| **Risk Level** | **Possible** (architectural concern) |

### Code

```
278:283:config_default.go
func (c *Config) GetHTTPClient(ctx context.Context) *retryablehttp.Client {
	if c.HTTPClient == nil {
		return retryablehttp.NewClient()
	}
	return c.HTTPClient
}
```

### Observation

When no custom HTTP client is configured, the library creates a default `retryablehttp.NewClient()` with no SSRF protections. This client is used for both `request_uri` fetching and `jwks_uri` fetching. The `retryablehttp` library adds automatic retries to HTTP requests, which could **amplify** SSRF attacks by sending multiple requests to internal endpoints.

Similarly, the `DefaultJWKSFetcherStrategy` (line 55 of `client_authentication_jwks_strategy.go`) also defaults to `retryablehttp.NewClient()`.

### Residual Risk

- The default HTTP clients have **no SSRF mitigations** (no IP filtering, no DNS rebinding protection).
- The **retry behavior** of `retryablehttp` could amplify the impact of SSRF attacks against availability.
- Integrators must proactively configure a hardened HTTP client; the library provides no guidance on this.

---

## Finding 4: PAR `request_uri` Injection Prevention

### Details

| Field | Value |
|-------|-------|
| **File** | `pushed_authorize_request_handler.go` |
| **Lines** | 55–58 |
| **Function** | `Fosite.NewPushedAuthorizeRequest()` |
| **Parameter** | `request_uri` |
| **Risk Level** | **Not vulnerable** (properly mitigated) |

### Code

```
55:58:pushed_authorize_request_handler.go
	// Reject the request if the "request_uri" authorization request
	// parameter is provided.
	if r.Form.Get("request_uri") != "" {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The request must not contain 'request_uri'."))
	}
```

### Observation

The PAR endpoint explicitly rejects requests that contain a `request_uri` parameter, preventing SSRF via the PAR flow. Additionally, `authorize_request_handler.go:144` prevents `request_uri` claims inside the JWT request object in PAR:

```
141:146:authorize_request_handler.go
	claims := token.Claims
	// Reject the request if the "request_uri" authorization request
	// parameter is provided.
	if requestURI, _ := claims["request_uri"].(string); isPARRequest && requestURI != "" {
		return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Pushed Authorization Requests can not contain the 'request_uri' parameter."))
	}
```

This is a **well-implemented mitigation** per the PAR specification (RFC 9126).

---

## Finding 5: PAR `request_uri` Consumption at Authorize Endpoint

### Details

| Field | Value |
|-------|-------|
| **File** | `authorize_request_handler.go` |
| **Lines** | 280–324 |
| **Function** | `Fosite.authorizeRequestFromPAR()` |
| **Parameter** | `request_uri` (from authorize endpoint form) |
| **Risk Level** | **Not vulnerable** (properly mitigated) |

### Code

```
287:291:authorize_request_handler.go
	requestURI := r.Form.Get("request_uri")
	if requestURI == "" || !strings.HasPrefix(requestURI, configProvider.GetPushedAuthorizeRequestURIPrefix(ctx)) {
		// nothing to do here
		return false, nil
	}
```

### Observation

When the authorize endpoint receives a `request_uri`, it first checks whether it starts with the PAR prefix (default: `urn:ietf:params:oauth:request_uri:`). PAR `request_uri` values are URN-based identifiers (not HTTP URLs), so they are **never used as fetch targets**. The session data is retrieved from the storage backend, not via HTTP.

This is **not an SSRF vector** — the `request_uri` is used as a storage key, not as a URL to fetch.

---

## Areas Analyzed with No SSRF Findings

| Area | Observation |
|------|-------------|
| **Token endpoint** (`access_request_handler.go`) | No outbound HTTP requests. Client authentication may trigger JWKS fetching (covered in Finding 2). |
| **Introspection endpoint** (`introspection_request_handler.go`) | No outbound HTTP requests. Only processes form data from the request. |
| **Revocation endpoint** (`revoke_handler.go`) | No outbound HTTP requests. Only processes form data. |
| **Device authorization** (`handler/rfc8628/`) | No outbound HTTP requests. Generates device/user codes locally. |
| **PKCE handler** (`handler/pkce/`) | No outbound HTTP requests. Only processes code_challenge/code_verifier parameters. |
| **JWT Bearer grant** (`handler/rfc7523/`) | No outbound HTTP requests. Keys are looked up from local storage, not fetched remotely. |
| **Verifiable Credentials** (`handler/verifiable/`) | No outbound HTTP requests. Only generates nonces. |
| **OpenID Connect flows** (`handler/openid/`) | No outbound HTTP requests in the handlers themselves. |
| **Redirect URI handling** (`authorize_helper.go`) | Redirect URIs are used for HTTP redirects (302/303 responses), not for server-side fetches. Validation includes allowlisting against registered URIs and `IsRedirectURISecure` checks. Not SSRF. |
| **`client_uri`, `logo_uri`, `policy_uri`, `tos_uri`** | **Not implemented** in Fosite. These OpenID Connect Dynamic Registration metadata fields are not present in the codebase. No server-side fetching of these URIs occurs. |
| **OpenID Connect Discovery** (`.well-known/openid-configuration`) | **Not implemented** in Fosite. The library does not fetch discovery documents. |
| **`httputil.ReverseProxy`** | **Not used** anywhere in the codebase. |

---

## Summary of SSRF-Relevant Outbound HTTP Request Sites

| # | File | Line | URL Source | Method | Mitigation |
|---|------|------|-----------|--------|------------|
| 1 | `authorize_request_handler.go` | 69 | `request.Form.Get("request_uri")` | `hc.Get(location)` | Allowlist via `GetRequestURIs()` |
| 2 | `client_authentication_jwks_strategy.go` | 111 | `oidcClient.GetJSONWebKeysURI()` | `hc.Do(req)` | Client registration data; caching |

---

## Recommendations for Integrators

1. **Validate client registration metadata**: When registering or updating OAuth2 clients, validate that `jwks_uri` and `request_uris` values:
   - Use only `https://` scheme
   - Do not resolve to private/internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8, ::1)
   - Do not point to cloud metadata endpoints
   - Point to expected external domains

2. **Configure a hardened HTTP client**: Supply a custom `Config.HTTPClient` and `JWKSFetcherStrategy` that includes:
   - A custom `http.Transport` with a `DialContext` function that blocks connections to private IP ranges
   - DNS rebinding protection (resolve DNS before connecting and validate the resolved IP)
   - Request timeouts
   - Response size limits
   - Scheme restrictions (HTTPS only)

3. **Consider response size limits**: The `request_uri` fetching uses `io.ReadAll()` with no size cap. Consider wrapping the response body with `io.LimitReader()`.

4. **Enforce HTTPS for `jwks_uri` and `request_uris`**: The library does not enforce HTTPS for these URIs. Integrators should enforce this at the client registration layer.

5. **Monitor and audit**: Log all outbound HTTP requests made by the JWKS fetcher and request_uri fetcher for security monitoring.

---

## Conclusion

Fosite has **two production code paths** that make server-side HTTP requests based on data associated with registered OAuth2 clients. Both have some mitigations in place (allowlisting for `request_uri`; client-registration-time control for `jwks_uri`), but **neither has network-layer SSRF protections**. The overall SSRF risk depends heavily on how the integrating application manages client registration and whether it configures hardened HTTP clients. The library itself does not provide built-in SSRF defenses beyond the application-layer allowlisting.
