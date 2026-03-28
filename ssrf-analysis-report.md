# SSRF Vulnerability Analysis Report: Ory Keto

**Project:** Ory Keto (Zanzibar-based authorization service)  
**Location:** `/workspace/ory-repos/keto/`  
**Date:** 2026-03-28  
**Scope:** Static source code analysis for Server-Side Request Forgery (SSRF)

---

## Executive Summary

Ory Keto has a **moderate SSRF attack surface** primarily concentrated in its **namespace configuration loading** subsystem, which can fetch OPL (Ory Permission Language) files from HTTP/HTTPS URLs. The project includes built-in SSRF mitigation infrastructure (`code.dny.dev/ssrf` library, private IP blocking) but this protection is **disabled by default** (`disallow_private_ip_ranges: false`). The core API handlers (check, expand, read, write relation tuples) do **not** accept URL-like parameters and are not directly exploitable for SSRF. Most HTTP client usage in the codebase is configuration-driven (admin-only) rather than user-input-driven.

---

## Finding 1: OPL Namespace Configuration Fetches Remote URLs (PRIMARY FINDING)

### File Path & Lines
- `internal/driver/config/opl_config_namespace_watcher.go` — lines 48–91
- `internal/driver/config/provider.go` — lines 239–249, 325–337, 347–374

### Endpoint/Function
`newOPLConfigWatcher()` → called from `Config.NamespaceManager()` → triggered at startup and on config change.

### Parameter
`namespaces.location` configuration key (string, accepts `http://`, `https://`, `file://`, `base64://` schemes).

### Observation
When the Keto configuration specifies `namespaces` as a map with a `location` key, the value is passed to `newOPLConfigWatcher()`, which:

1. Parses the URL scheme (`opl_config_namespace_watcher.go:56–61`)
2. For `http`/`https` schemes, calls `c.Fetcher().FetchContext(ctx, target)` (`opl_config_namespace_watcher.go:77`)
3. `Config.Fetcher()` creates a `fetcher.Fetcher` that makes an HTTP GET request to the provided URL (`provider.go:239–249`)
4. The fetcher uses `httpx.NewResilientClient()` which, by default, does **not** block private/internal IP ranges

The configuration example:
```yaml
namespaces:
  location: https://attacker.example.com/opl.ts
```

The `Fetcher()` method conditionally enables SSRF protection only if `clients.http.disallow_private_ip_ranges` is `true`:
```go
func (k *Config) Fetcher() *fetcher.Fetcher {
    opts := []httpx.ResilientOptions{}
    if k.p.Bool("clients.http.disallow_private_ip_ranges") {
        opts = append(opts, httpx.ResilientClientDisallowInternalIPs())
    }
    return fetcher.NewFetcher(
        fetcher.WithClient(httpx.NewResilientClient(opts...)),
    )
}
```

### Risk Level
**Possible** — Configuration-driven, not API-driven.

### Reasoning
This is a configuration-time SSRF vector. The `namespaces.location` field is set in the Keto configuration file (YAML/JSON/TOML), which is typically controlled by an administrator. It is **not** exposed via any REST or gRPC API endpoint. However:
- If configuration is managed by an orchestration system that accepts user input (e.g., a multi-tenant platform where tenants can configure their own Keto instance), this becomes exploitable.
- The `disallow_private_ip_ranges` config defaults to `false` (confirmed in `embedx/config.schema.json:444`), meaning even private/internal IPs are reachable by default.
- The test at `internal/driver/config/provider_test.go:226–232` explicitly tests that HTTP URLs work and that private IPs are only blocked when `disallow_private_ip_ranges: true`.

---

## Finding 2: Generic Fetcher Library Supports Remote URL Fetching

### File Path & Lines
- `oryx/fetcher/fetcher.go` — lines 97–157
- `oryx/osx/file.go` — lines 148–189

### Endpoint/Function
`fetcher.Fetcher.FetchBytes()`, `fetcher.Fetcher.fetchRemote()`, `osx.ReadFileFromAllSources()`

### Parameter
`source` string parameter accepting `http://`, `https://`, `file://`, `base64://` schemes.

### Observation
The `fetcher` package (`oryx/fetcher/fetcher.go`) is a general-purpose file/URL fetcher used across the Ory ecosystem. It:
1. Accepts any URL starting with `http://` or `https://` (`fetcher.go:99`)
2. Creates an HTTP GET request to the URL (`fetcher.go:131`)
3. Returns the full response body (`fetcher.go:156`)
4. Has an optional `WithMaxHTTPMaxBytes` limit but no built-in URL validation or IP filtering

Similarly, `osx.ReadFileFromAllSources()` (`osx/file.go:144`) supports HTTP fetching via `o.hc.Get(parsed.String())` at line 179.

Neither of these libraries performs any SSRF mitigation on its own — they rely on the caller to provide a properly configured HTTP client with SSRF protections.

### Risk Level
**Possible** — Library-level concern; risk depends on how callers configure the HTTP client.

### Reasoning
The fetcher library is a building block. In Keto, it is called from `Config.Fetcher()` which conditionally adds IP restriction. However, the default is permissive. If the fetcher is reused in other contexts (e.g., new features added to Keto) without configuring private IP blocking, SSRF would be possible.

---

## Finding 3: SSRF Protection Exists but Is Disabled by Default

### File Path & Lines
- `oryx/httpx/ssrf.go` — lines 1–133
- `oryx/httpx/resilient_client.go` — lines 68–71, 88–114
- `embedx/config.schema.json` — lines 440–445

### Endpoint/Function
`httpx.NewResilientClient()` with `ResilientClientDisallowInternalIPs()` option.

### Parameter
`clients.http.disallow_private_ip_ranges` configuration key.

### Observation
Keto includes a sophisticated SSRF mitigation system:
1. `oryx/httpx/ssrf.go` implements `noInternalIPRoundTripper` using the `code.dny.dev/ssrf` library
2. It blocks connections to private IPv4 ranges (10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16) and private IPv6 ranges
3. The protection is activated by calling `ResilientClientDisallowInternalIPs()`
4. However, the `disallow_private_ip_ranges` config key defaults to **`false`**:
   ```json
   "disallow_private_ip_ranges": {
     "type": "boolean",
     "default": false
   }
   ```

Additionally, the `noInternalIPRoundTripper` supports an exception list (`internalIPExceptions`) using glob-matching, allowing specific internal URLs to be whitelisted even when protection is enabled.

### Risk Level
**Possible** — The mitigation infrastructure exists but is opt-in.

### Reasoning
This is a defense-in-depth configuration issue. Organizations that deploy Keto without explicitly setting `disallow_private_ip_ranges: true` leave SSRF protections disabled. The SSRF library itself is robust (it operates at the TCP dial level via `net.Dialer.Control`, preventing TOCTOU DNS rebinding attacks), but only when enabled.

---

## Finding 4: Tracing Configuration Accepts External Server URLs

### File Path & Lines
- `oryx/otelx/otlp.go` — lines 21–68 (`SetupOTLP`)
- `oryx/otelx/jaeger.go` — lines 30–88 (`SetupJaeger`)
- `oryx/otelx/zipkin.go` — lines 15–17 (`SetupZipkin`)
- `oryx/otelx/config.go` — lines 12–42 (config structs)

### Endpoint/Function
`SetupOTLP()`, `SetupJaeger()`, `SetupZipkin()` — called at startup.

### Parameter
- `tracing.providers.otlp.server_url`
- `tracing.providers.jaeger.local_agent_address`
- `tracing.providers.jaeger.sampling.server_url`
- `tracing.providers.zipkin.server_url`

### Observation
Tracing configuration allows specifying external endpoints where trace spans are sent:
- **OTLP**: `otlptracehttp.WithEndpoint(c.Providers.OTLP.ServerURL)` — sends HTTP requests to the configured endpoint
- **Jaeger**: `jaeger.WithAgentHost(host), jaeger.WithAgentPort(port)` — sends UDP packets to the configured agent; additionally `jaegerremote.WithSamplingServerURL(samplingServerURL)` makes HTTP requests
- **Zipkin**: `zipkin.New(c.Providers.Zipkin.ServerURL)` — sends HTTP requests to the Zipkin endpoint

None of these use the `disallow_private_ip_ranges` protection. They use their respective library clients directly, not the Keto-configured resilient HTTP client.

### Risk Level
**Possible** — Configuration-driven, admin-only, but no IP validation applied.

### Reasoning
If an attacker gains control of the Keto configuration (e.g., through a config injection vulnerability in a management plane), they could direct tracing data to internal services. The Jaeger sampling server URL is particularly notable because it causes Keto to make periodic HTTP requests to fetch sampling strategies. However, this is a configuration-only vector with no API exposure.

---

## Finding 5: JWK Fetcher Can Retrieve Keys from Remote URLs

### File Path & Lines
- `oryx/jwksx/fetcher.go` — lines 28–74 (deprecated `Fetcher`)
- `oryx/jwksx/fetcher_v2.go` — lines 80–169 (`FetcherNext`)

### Endpoint/Function
`jwksx.Fetcher.GetKey()`, `jwksx.FetcherNext.ResolveKeyFromLocations()`

### Parameter
`remote` (string URL) for v1, `locations` (string slice of URLs) for v2.

### Observation
The JWK fetcher library fetches JSON Web Key Sets from remote URLs:
- **v1 (deprecated)**: Uses `http.DefaultClient.Get(f.remote)` with no URL validation (`fetcher.go:47`)
- **v2**: Uses `fetcher.NewFetcher()` to fetch from locations, which supports `http://`, `https://`, `file://`, and `base64://` schemes (`fetcher_v2.go:154`)

In v2, an optional `WithHTTPClient` can be passed to use a configured client, but if not provided, it defaults to `httpx.NewResilientClient()` without IP restrictions.

### Risk Level
**Possible** — Library code; risk depends on whether JWK fetching is used in Keto.

### Reasoning
I found no direct usage of the JWK fetcher in Keto's core code (it appears to be part of the shared `ory/x` library). If Keto adds JWT-based authentication in the future using this library, the JWK URL source would need to be validated. Currently, this is a latent risk.

---

## Finding 6: Reverse Proxy in Shared Library

### File Path & Lines
- `oryx/proxy/proxy.go` — lines 277–300

### Endpoint/Function
`proxy.New()` — creates an `httputil.ReverseProxy`.

### Parameter
`HostConfig.UpstreamHost`, `HostConfig.UpstreamScheme` — set by the `HostMapper` callback.

### Observation
The proxy package implements a reverse proxy using `httputil.ReverseProxy`. The upstream target is determined by the `HostMapper` function provided at creation time. By default, it uses `http.DefaultTransport` (line 284).

### Risk Level
**Possible** — Library code; not used in Keto's core.

### Reasoning
The reverse proxy is part of the shared `ory/x` library and does not appear to be used by Keto's own server. It would be relevant if Keto were deployed behind this proxy component, but Keto's daemon (`internal/driver/daemon.go`) sets up its own HTTP servers directly without using this proxy. This is a latent risk if the proxy is adopted in the future.

---

## Finding 7: DSN (Database Connection String) from Configuration

### File Path & Lines
- `internal/driver/config/provider.go` — lines 231–237

### Endpoint/Function
`Config.DSN()` — returns the database connection string.

### Parameter
`dsn` configuration key.

### Observation
The DSN is read from configuration and used to connect to the database. It supports various SQL databases (PostgreSQL, MySQL, CockroachDB, SQLite). The DSN is not subject to SSRF protections (it's a direct database connection, not an HTTP request).

### Risk Level
**Possible** — Configuration-driven, standard database connection.

### Reasoning
While a malicious DSN could potentially cause connections to internal database servers, this is a standard database configuration pattern and not typically classified as SSRF. The DSN is set via configuration files or environment variables, not via API input.

---

## Finding 8: httploader Import for JSON Schema Validation

### File Path & Lines
- `internal/driver/config/provider.go` — line 15

### Endpoint/Function
Side-effect import: `_ "github.com/ory/jsonschema/v3/httploader"`

### Parameter
JSON Schema `$ref` values pointing to remote URLs.

### Observation
The `httploader` package is imported as a side effect, which registers an HTTP loader for the `jsonschema` validator. This allows JSON Schema `$ref` references to resolve remote schemas over HTTP. If any schema references external URLs, the validator will fetch them.

### Risk Level
**Possible** — The schema files are embedded at build time, not user-supplied.

### Reasoning
The config schema (`embedx/config.schema.json`) uses `$ref` to reference `ory://tracing-config`, which is a registered in-memory schema, not an HTTP URL. However, the httploader capability means that if any schema were to reference an HTTP URL, it would be fetched without SSRF protection. This is a latent risk.

---

## Findings NOT Present (Negative Results)

### No SSRF in API Handlers
The core REST/gRPC API endpoints do **not** accept URL parameters that trigger outbound requests:
- `GET /relation-tuples` — accepts `namespace`, `object`, `relation`, `subject_id`, `subject_set.*` query params (all string identifiers, not URLs)
- `PUT /admin/relation-tuples` — accepts JSON body with relation tuple fields (string identifiers)
- `DELETE /admin/relation-tuples` — accepts query params for relation tuple fields
- `PATCH /admin/relation-tuples` — accepts JSON body with patch deltas
- `GET /relation-tuples/check` — accepts relation tuple query params
- `POST /relation-tuples/check` — accepts JSON body with relation tuple
- `POST /relation-tuples/batch/check` — accepts JSON body with tuple array
- `GET /relation-tuples/expand` — accepts subject set query params
- `GET /namespaces` — no parameters, returns configured namespaces
- `POST /opl/syntax/check` — accepts OPL text in body, parses it locally (no URL fetching)

### No Webhook/Callback Mechanisms
Keto does not implement webhooks, callback URLs, or notification endpoints that could be SSRF vectors.

### No User-Controllable URL Parameters in gRPC
The gRPC service definitions (`proto/ory/keto/`) accept only typed relation tuple fields (strings for namespace, object, relation, subject). No URL-typed fields exist in the protobuf definitions.

### OPL Evaluation Does Not Fetch External Resources
The OPL parser (`schema/parser.go`) is a pure in-memory parser. OPL files are loaded once (at config time) and then parsed locally. OPL evaluation at check/expand time does not trigger network requests.

---

## Summary Table

| # | Location | Vector | User-Controllable? | SSRF Mitigation | Risk Level |
|---|----------|--------|--------------------|-----------------| -----------|
| 1 | `opl_config_namespace_watcher.go:48-91` | OPL config fetches HTTP URLs | Config-driven (admin) | Optional (`disallow_private_ip_ranges`, default=off) | **Possible** |
| 2 | `oryx/fetcher/fetcher.go:97-157` | Generic URL fetcher library | Depends on caller | None built-in; relies on caller's HTTP client | **Possible** |
| 3 | `oryx/httpx/ssrf.go` + `config.schema.json:440` | SSRF protection disabled by default | N/A (configuration) | Exists but default=`false` | **Possible** |
| 4 | `oryx/otelx/otlp.go`, `jaeger.go`, `zipkin.go` | Tracing endpoints | Config-driven (admin) | None | **Possible** |
| 5 | `oryx/jwksx/fetcher.go`, `fetcher_v2.go` | JWK remote fetching | Library code (unused in Keto core) | None by default | **Possible** |
| 6 | `oryx/proxy/proxy.go:277-300` | Reverse proxy | Library code (unused in Keto core) | None | **Possible** |
| 7 | `provider.go:231-237` | Database DSN | Config-driven (admin) | N/A (not HTTP) | **Possible** |
| 8 | `provider.go:15` (httploader import) | JSON Schema HTTP loader | Build-time schemas | None | **Possible** |

---

## Recommendations

1. **Enable `disallow_private_ip_ranges` by default** — Change the default from `false` to `true` in `embedx/config.schema.json`. This is the single most impactful change to reduce SSRF risk.

2. **Apply IP restrictions to tracing clients** — The tracing setup functions (`SetupOTLP`, `SetupJaeger`, `SetupZipkin`) should use HTTP clients with the same SSRF protections as the fetcher.

3. **Add URL scheme validation to namespace config** — Consider restricting `namespaces.location` to `file://` and `base64://` schemes only, or requiring explicit opt-in for `http://`/`https://` schemes.

4. **Document SSRF hardening** — Add documentation advising operators to enable `clients.http.disallow_private_ip_ranges: true` in production deployments.

5. **Audit future feature additions** — Any new feature that uses the `fetcher` or `osx.ReadFileFromAllSources()` libraries should ensure the HTTP client is configured with `ResilientClientDisallowInternalIPs()`.
