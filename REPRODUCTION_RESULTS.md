# Vulnerability Reproduction Results

**Nexus Instance:** sonatype/nexus3:latest (v3.90.2-06)  
**Test Date:** 2026-03-27  
**Environment:** Docker container on Linux x86_64  

---

## Test Methodology

Two test rounds were performed:

1. **Default configuration** — Fresh `docker run` with zero modifications. Anonymous access OFF, scripting disabled, random admin password generated. Only the EULA was accepted via API.
2. **Modified configuration** — Anonymous access ON, scripting enabled. Used to verify sandbox bypass and auth-dependent findings.

This distinction is critical for HackerOne — only vulnerabilities exploitable on **default configuration** should be filed as high-confidence reports.

---

## Default Configuration Test Results

### EXPLOITABLE on Default Config (No Modifications Needed)

#### 1. Unauthenticated Information Disclosure via `/v1/formats/upload-specs`

**Requires:** Nothing — no auth, no config change.

```
GET /service/rest/v1/formats/upload-specs (NO AUTH, anonymous access OFF)
HTTP 200 — Returns complete upload field definitions for all 12 formats
```

Leaked formats: apt, maven2, raw, npm, nuget, rubygems, helm, yum, r, pypi, terraform, swift  
Each entry includes field names, types, optional flags, and grouping — reveals the internal data model.

**Also leaks:** The `Server` response header exposes the exact version:
```
Server: Nexus/3.90.2-06 (COMMUNITY)
```
This is returned on every response, including unauthenticated ones, aiding targeted exploit development.

#### 2. SSRF via Proxy Repository — Private Networks Allowed by Default

**Requires:** Admin credentials only (default config, no property changes).

```
POST /service/rest/v1/repositories/raw/proxy
Body: {"proxy": {"remoteUrl": "http://127.0.0.1:4444/"}}
HTTP 201 Created
```

**Server logs confirm the TCP connection to loopback was attempted:**
```
Connect to 127.0.0.1:4444 [/127.0.0.1] failed: Connection refused for http://127.0.0.1:4444
```

Nexus accepted `127.0.0.1` as a valid proxy target and attempted the connection. No SSRF filter blocked it. The `nexus.proxy.allowPrivateNetworks` defaults to `true`.

#### 3. SSRF via SSL Certificate Retrieval

**Requires:** Admin credentials only (default config, no property changes).

```
GET /service/rest/v1/security/ssl?host=127.0.0.1&port=443
Response: {"message": "\"Could not retrieve an SSL certificate from '127.0.0.1:443'\""}
```

The error message proves Nexus attempted a TLS connection to `127.0.0.1:443`. No `AntiSsrfHelper` validation was applied. Any IP address is accepted.

#### 4. SQL Injection Pattern (MyBatis `${}`) — Source Code Confirmed

Verified in source: `ContentRepositoryDAO.xml` uses `'${repositoryName}'` (raw string substitution). `SearchTableDAO.xml` uses `${filter}`, `${sortColumnName}`, `${componentId}` as raw SQL. This is an architectural vulnerability pattern — exploitability depends on whether user-controlled data reaches these parameters through any code path.

#### 5. Unsafe Java Deserialization — Source Code Confirmed

Verified in source: `QuartzObjectBuilder.java` line 80 uses `ObjectInputStream.readObject()` with no JEP 290 filter. Exploitable if an attacker can write to the Quartz JDBC job store (via SQLi or DB compromise).

#### 6. Legacy Password Hashing (MD5/SHA-1) — Source Code Confirmed

Verified in source: `LegacyNexusPasswordService.java` uses unsalted MD5 and SHA-1 with 1 iteration. Still active for legacy password verification. Exploitable if attacker obtains the user database.

---

### NOT Exploitable on Default Config (Require Configuration Changes)

#### 7. Groovy RCE (Sandbox Bypass)

**Default behavior:** Script creation returns `410 Gone` with message "Creating and updating scripts is disable".

**Requires:** Admin must add `nexus.scripts.allowCreation=true` to `nexus.properties` and restart.

**When enabled:** The sandbox is trivially bypassable:
- `"id".execute().text` → `uid=200(nexus) gid=200(nexus) groups=200(nexus)`
- `new File("/etc/passwd").text` → full file contents
- `ProcessBuilder` → not blocked
- `container.lookup(...)` → access to entire Spring component graph

**HackerOne note:** File this as a sandbox bypass issue, not an RCE-from-default. The sandbox is so weak it provides no real security even when scripting is intentionally enabled.

#### 8. Default Credentials (`admin123`)

**Default behavior:** Random UUID password generated and written to `/nexus-data/admin.password`. The `admin123` constant is a fallback that only activates when the password file write fails.

**HackerOne note:** This is a code-level finding (hardcoded credential in source, silent fallback on error) rather than a runtime default-credential issue. Still worth reporting for the error-path behavior.

#### 9. Stored XSS via Branding

**Requires:** Admin access to set branding HTML + the branding capability to be present and enabled. The `dangerouslySetInnerHTML` sink exists in source but requires admin-controlled input.

#### 10. Path Traversal (Dev-Mode Resources)

**Requires:** `NEXUS_RESOURCE_DIRS` or `nexus.resource.dirs` to be set — not set by default, only in development environments.

---

## Summary Matrix

| # | Vulnerability | Default Config | Auth Required | Confirmed |
|---|--------------|----------------|---------------|-----------|
| 1 | Info Disclosure: upload-specs | **YES** | **None** | **LIVE** |
| 2 | SSRF: Proxy to internal nets | **YES** | Admin | **LIVE** (server logs) |
| 3 | SSRF: Certificate retrieval | **YES** | Admin | **LIVE** (error response) |
| 4 | SQL Injection (MyBatis `${}`) | **YES** (code pattern) | Varies | Source code |
| 5 | Unsafe Deserialization (Quartz) | **YES** (code pattern) | DB access | Source code |
| 6 | Legacy Password Hashing | **YES** (code pattern) | DB access | Source code |
| 7 | Groovy RCE (sandbox bypass) | No — scripting disabled | Admin + config | **LIVE** (when enabled) |
| 8 | Default Credentials (admin123) | No — random password | None | Source code |
| 9 | Stored XSS (branding) | No — needs branding | Admin | Source code |
| 10 | Path Traversal (dev-mode) | No — needs env var | None | Source code |

---

## Recommended HackerOne Filing Strategy

**File with high confidence (exploitable on default):**
1. SSRF via Proxy — default `allowPrivateNetworks=true`, admin auth only
2. SSRF via Certificate Retrieval — no SSRF filter, admin auth only
3. Unauthenticated Info Disclosure — upload-specs + version header, zero auth

**File as code-quality / design issues:**
4. Groovy sandbox bypass — real but requires non-default config
5. MyBatis `${}` SQL injection pattern — architectural risk
6. Unsafe deserialization — requires DB access chain
7. Legacy password hashing — requires DB access to exploit

**Consider skipping (may be rejected as informational):**
8. Default credentials — random password is the actual default now
9. Stored XSS — admin-to-admin attack
10. Path traversal — dev-mode only
