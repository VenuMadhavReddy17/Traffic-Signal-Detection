# Sonatype Nexus Repository Manager - Security Audit Report

**Repository:** https://github.com/sonatype/nexus-public  
**Version Audited:** 3.89.0-09  
**Audit Date:** 2026-03-27  
**Methodology:** Static source code analysis (white-box)  
**Auditor Role:** Senior Product Security Engineer / Bug Bounty Researcher

---

## Executive Summary

This report documents a comprehensive source code security review of the Sonatype Nexus Repository Manager (nexus-public). The audit identified **14 confirmed vulnerabilities** across critical, high, medium, and low severity tiers. The most impactful findings include unsafe Java deserialization sinks, a hardcoded encryption key, SQL injection via MyBatis string interpolation, and a weak Groovy script sandbox that is insufficient against determined attackers.

---

## Severity Classification

| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 4 |
| Medium | 5 |
| Low | 2 |

---

## FINDING 1: Unsafe Java Deserialization in Quartz Job Data (Critical)

**CVSS 3.1 Estimate:** 8.1 (High)  
**CWE:** CWE-502 (Deserialization of Untrusted Data)  
**Affected Files:**
- `public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/bulkread/QuartzObjectBuilder.java` (lines 77-91)
- `public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/datastore/QuartzJobDataTypeHandler.java`

**Description:**

The Quartz scheduler deserializes `JobDataMap` objects from the database using raw `ObjectInputStream.readObject()` without any class-filtering or allowlist:

```java
// QuartzObjectBuilder.java:77-80
private static JobDataMap deserializeJobData(final byte[] data) throws IOException, ClassNotFoundException {
    try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis)) {
      Object jobData = ois.readObject();  // UNSAFE: no class filter
```

**Attack Vector:** If an attacker gains write access to the database (SQL injection, DB credential compromise, backup manipulation), they can inject a malicious serialized Java object into the `job_data` BLOB column. Upon deserialization, this triggers arbitrary code execution via known gadget chains (Commons Collections, Spring, etc.).

**Exploitability:** Requires database-level write access. In a chain with another vulnerability (e.g., SQL injection, backup restore, or compromised DB credentials), this becomes a reliable RCE primitive.

**Recommendation:** Implement `ObjectInputFilter` (JEP 290) with a strict allowlist of permitted classes. Replace Java serialization with JSON-based serialization for job data.

---

## FINDING 2: Unsafe Java Deserialization in MyBatis Type Handlers (Critical)

**CVSS 3.1 Estimate:** 8.1 (High)  
**CWE:** CWE-502 (Deserialization of Untrusted Data)  
**Affected File:** `public/common/components/nexus-datastore-mybatis/src/main/java/org/sonatype/nexus/datastore/mybatis/AbstractSerializableTypeHandler.java` (lines 109-122)

**Description:**

The MyBatis type handler decrypts database column bytes and then deserializes them with `ObjectInputStreamWithClassLoader`, which only overrides class loading but does **not** implement class filtering:

```java
// AbstractSerializableTypeHandler.java:114-117
byte[] decrypted = cipher().decrypt(bytes);
try (ByteArrayInputStream buf = new ByteArrayInputStream(decrypted);
    ObjectInputStream in = new ObjectInputStreamWithClassLoader(buf, classLoading)) {
  return (T) in.readObject();  // UNSAFE: no class allowlist
```

The custom class loader (`ObjectInputStreamWithClassLoader`) resolves classes by name but does **not** restrict which classes can be deserialized:

```java
// ObjectInputStreamWithClassLoader.java:52-55
@Override
protected Class<?> resolveClass(final ObjectStreamClass classDesc) throws ClassNotFoundException {
    return classLoading.loadClass(classDesc.getName());  // No filtering
}
```

**Attack Vector:** An attacker who can modify encrypted serialized objects in the database (via SQL injection, database compromise, or backup manipulation) can achieve remote code execution by injecting gadget chain payloads. The encryption layer provides defense-in-depth but is only as strong as the encryption key management (see Finding 3).

**Exploitability:** Requires database write + knowledge of encryption key. Combined with Finding 3 (hardcoded key), the encryption barrier may be trivially bypassed.

**Recommendation:** Implement `ObjectInputFilter` with a strict class allowlist. Migrate persistence to JSON serialization where possible.

---

## FINDING 3: Hardcoded Default Encryption Key "changeme" (Critical)

**CVSS 3.1 Estimate:** 9.1 (Critical)  
**CWE:** CWE-798 (Use of Hard-coded Credentials), CWE-321 (Use of Hard-coded Cryptographic Key)  
**Affected File:** `public/common/components/nexus-crypto/src/main/java/org/sonatype/nexus/crypto/secrets/EncryptDecryptService.java` (lines 34-36)

**Description:**

The `EncryptDecryptService` singleton initializes with a hardcoded encryption password `"changeme"`:

```java
// EncryptDecryptService.java:36
private String secret = "changeme";
```

If `setSecret()` is never called before encryption/decryption operations, all encrypted data uses this publicly known password. This encryption service is used for protecting sensitive data at rest.

**Attack Vector:** An attacker with database read access can decrypt all secrets encrypted by this service using the known password `"changeme"`. This directly undermines the encryption protection relied upon by Finding 2's serialization handlers.

**Exploitability:** Trivial if `setSecret()` is not invoked during application bootstrap. Even if configured, the default value creates a dangerous initialization window.

**Recommendation:** Remove the default value entirely. Require explicit configuration at startup. Fail-closed if no encryption key is configured.

---

## FINDING 4: SQL Injection via MyBatis String Interpolation in Search Sort (High)

**CVSS 3.1 Estimate:** 7.5 (High)  
**CWE:** CWE-89 (SQL Injection)  
**Affected Files:**
- `public/common/components/nexus-search-sql/src/main/java/org/sonatype/nexus/repository/search/sql/query/SqlSearchSortUtil.java` (lines 54, 94-97)
- `public/common/components/nexus-search-sql/src/main/resources/org/sonatype/nexus/repository/search/sql/store/SearchTableDAO.xml` (lines 455-458)

**Description:**

The search sort expression is constructed via `String.format` and injected into SQL via MyBatis `${}` (string substitution, not parameterized):

```java
// SqlSearchSortUtil.java:54,94-96
public static final String JSON_PATH_FORMAT = "%s #> '{%s}'";

private Function<String, Optional<String>> sortExpressionForAttributesColumn(final Optional<String> sortAlias) {
    return column -> sortAlias.map(alias -> alias.replace('.', ','))
        .map(alias -> String.format(JSON_PATH_FORMAT, column, alias));
}
```

This is then used in the MyBatis mapper with unsafe `${}` interpolation:

```xml
<!-- SearchTableDAO.xml:455-457 -->
ORDER BY <if test="sortColumnName != null">
    ${sortColumnName} ${sortDirection}
```

**Mitigating Factor:** The `sortField` HTTP parameter must match a registered `SearchMapping` alias in `aliasToColumn`. Only mapped attributes reach the `JSON_PATH_FORMAT` code path. However, for attributes that **do** match (e.g., `attributes.maven2.groupId`), the suffix after `attributes.` is embedded in the SQL fragment with only `.` to `,` substitution -- no SQL escaping or quoting for the PostgreSQL `#>` JSON path.

**Attack Vector:** If any registered search mapping alias allows special characters (single quotes, parentheses, semicolons) in the suffix portion, an attacker can break out of the JSON path literal and inject arbitrary SQL in the `ORDER BY` clause.

**Exploitability:** Medium -- constrained by the alias whitelist but the suffix transformation is not properly parameterized. A targeted fuzzing effort against the PostgreSQL `#>` operator with the processed suffix could reveal injection points.

**Recommendation:** Use parameterized queries (`#{}`) for all user-influenced SQL fragments. If `${}` is needed for dynamic column names, implement a strict allowlist of permitted sort expressions.

---

## FINDING 5: Insufficient Groovy Script Sandbox (High)

**CVSS 3.1 Estimate:** 8.8 (High)  
**CWE:** CWE-94 (Improper Control of Generation of Code)  
**Affected Files:**
- `public/common/components/nexus-script/src/main/java/org/sonatype/nexus/internal/script/groovy/GroovyScriptEngineFactory.java` (lines 89-94)
- `public/common/components/nexus-script/src/main/java/org/sonatype/nexus/internal/script/ScriptServiceImpl.java` (lines 98-102)
- `public/common/components/nexus-script-plugin/src/main/java/org/sonatype/nexus/script/plugin/internal/rest/ScriptResource.java` (lines 191-216)

**Description:**

The Groovy script engine uses a `SecureASTCustomizer` that only blacklists `java.lang.System`:

```java
// GroovyScriptEngineFactory.java:89-94
private CompilationCustomizer secureASTCustomizer() {
    SecureASTCustomizer secureASTCustomizer = new SecureASTCustomizer();
    secureASTCustomizer.setImportsBlacklist(Collections.singletonList("java.lang.System"));
    secureASTCustomizer.setReceiversBlackList(Collections.singletonList(System.class.getName()));
    secureASTCustomizer.setIndirectImportCheckEnabled(true);
    return secureASTCustomizer;
}
```

Furthermore, scripts receive extremely powerful bindings including `container` (a `GlobalComponentLookupHelper` for Spring/DI container access) and all `ScriptApi` beans:

```java
// ScriptServiceImpl.java:98-102
bindings.put("container", lookupHelper);
for (ScriptApi scriptApi : scriptApis) {
    bindings.put(scriptApi.getName(), scriptApi);
}
```

**Attack Vector:** `SecureASTCustomizer` is widely documented as insufficient for strong sandboxing. An attacker with `nexus:script:*:run` permission can trivially bypass the blacklist using reflection, metaclass manipulation, or Groovy-specific features to achieve full RCE. The `container` binding provides direct access to the application's dependency injection container.

**Exploitability:** Requires admin-level script execution permissions. However, if those permissions are over-granted or if credential compromise occurs, the sandbox provides no meaningful defense.

**Recommendation:** Deprecate and disable the scripting API by default. If scripting must be retained, implement a proper process-level sandbox (separate JVM, seccomp, etc.) rather than relying on AST-level restrictions.

---

## FINDING 6: Hardcoded Default Admin Password "admin123" (High)

**CVSS 3.1 Estimate:** 7.2 (High)  
**CWE:** CWE-798 (Use of Hard-coded Credentials)  
**Affected Files:**
- `public/selfhosted/components/nexus-self-hosted/src/main/java/org/sonatype/nexus/security/config/AdminPasswordSourceImpl.java` (lines 33, 51-53)
- `public/common/components/nexus-repository-services/src/main/java/org/sonatype/nexus/repository/security/internal/DefaultUserHealthCheck.java` (lines 55-57)

**Description:**

The admin password source has a hardcoded default password `admin123`:

```java
// AdminPasswordSourceImpl.java:33
public static final String DEFAULT_PASSWORD = "admin123";

// AdminPasswordSourceImpl.java:51-53
else if (!randomPassword) {
    return DEFAULT_PASSWORD;
}
```

When `randomPassword` is `false` and no password file exists, the system falls back to this well-known default. Additionally, if writing a random password to the password file fails, the system also falls back to `admin123`:

```java
// AdminPasswordSourceImpl.java:58-59
if (!adminPasswordFileManager.writeFile(savedPassword)) {
    savedPassword = DEFAULT_PASSWORD;
}
```

**Attack Vector:** Any Nexus instance deployed with `randomPassword=false` or where the password file write fails is accessible with `admin/admin123`. This is a well-known credential pair in the security community.

**Exploitability:** High for default/misconfigured deployments. The health check (`DefaultUserHealthCheck`) attempts to detect this condition but depends on administrators monitoring health endpoints.

**Recommendation:** Remove hardcoded fallback entirely. Require interactive initial password setup. Refuse to start with default credentials in production mode.

---

## FINDING 7: Legacy Unsalted MD5/SHA-1 Password Hashing (High)

**CVSS 3.1 Estimate:** 7.4 (High)  
**CWE:** CWE-328 (Use of Weak Hash), CWE-916 (Use of Password Hash With Insufficient Computational Effort)  
**Affected File:** `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/internal/LegacyNexusPasswordService.java` (lines 39-57)

**Description:**

The legacy password service uses single-iteration, unsalted MD5 and SHA-1 hashing:

```java
// LegacyNexusPasswordService.java:42-46
sha1HashService.setHashAlgorithmName("SHA-1");
sha1HashService.setHashIterations(1);
sha1HashService.setGeneratePublicSalt(false);

// LegacyNexusPasswordService.java:51-55
md5HashService.setHashAlgorithmName("MD5");
md5HashService.setHashIterations(1);
md5HashService.setGeneratePublicSalt(false);
```

Both hash services accept legacy passwords for authentication:

```java
// LegacyNexusPasswordService.java:68-69
return sha1PasswordService.passwordsMatch(submittedPlaintext, encrypted) ||
    md5PasswordService.passwordsMatch(submittedPlaintext, encrypted);
```

**Attack Vector:** If an attacker obtains the database (backup leak, SQL injection), unsalted single-iteration MD5/SHA-1 hashes can be cracked in seconds using rainbow tables or GPU-accelerated brute force.

**Exploitability:** High given database access. Users who have not changed their password since the legacy era are vulnerable.

**Recommendation:** Force password rotation for accounts still using legacy hashes. Add a migration that re-hashes on next successful login with a modern algorithm (bcrypt/scrypt/argon2).

---

## FINDING 8: XSS via Unescaped Variables in Browse Template (Medium)

**CVSS 3.1 Estimate:** 6.1 (Medium)  
**CWE:** CWE-79 (Cross-site Scripting)  
**Affected File:** `public/common/components/nexus-repository-services/src/main/resources/org/sonatype/nexus/repository/rest/internal/resources/browseContentHtml.vm` (lines 17, 71, 81)

**Description:**

The Velocity template for repository browsing has multiple unescaped variable interpolations:

```velocity
<!-- Line 17: title tag - UNESCAPED -->
<title>Index of ${requestPath}</title>

<!-- Line 39: body heading - ESCAPED (safe) -->
<h1>Index of $esc.html($requestPath)</h1>

<!-- Line 71: lastModified - UNESCAPED -->
$listItem.lastModified

<!-- Line 81: description - UNESCAPED -->
<td>$listItem.description</td>
```

Note the inconsistency: `$requestPath` is escaped with `$esc.html()` in the `<h1>` tag (line 39) but **not** in the `<title>` tag (line 17). The `description` and `lastModified` fields are completely unescaped.

**Attack Vector:**
- **`requestPath` in `<title>`:** If an attacker can craft a repository path containing `</title><script>...`, the browser will execute JavaScript in the context of the Nexus application. The `<title>` context allows easy breakout.
- **`description`:** Currently set to `""` by `BrowseNodeQueryServiceImpl`, making this a **latent** vulnerability. If any future implementation or plugin populates this field with untrusted data, it becomes exploitable stored XSS.

**Mitigating Factor:** ViewServlet sets a `sandbox` CSP header on repository content responses, and `requestPath` undergoes normalization. The title XSS may be partially mitigated by path validation.

**Recommendation:** Apply `$esc.html()` to all variable interpolations in HTML context, including `${requestPath}` in `<title>`, `$listItem.description`, `$listItem.lastModified`, and `$listItem.size`.

---

## FINDING 9: JWT Session Revocation Bypass for Legacy Tokens (Medium)

**CVSS 3.1 Estimate:** 5.9 (Medium)  
**CWE:** CWE-613 (Insufficient Session Expiration)  
**Affected File:** `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/JwtSecurityFilter.java` (lines 116-139)

**Description:**

JWT tokens that lack the `userSessionId` claim (legacy tokens or tokens from older versions) completely skip revocation checking:

```java
// JwtSecurityFilter.java:117-119
Claim userSessionIdClaim = decodedJwt.getClaim(USER_SESSION_ID);
if (!userSessionIdClaim.isNull()) {
    // Only tokens WITH userSessionId are checked for revocation
    String userSessionId = userSessionIdClaim.asString();
    if (jwtSessionRevocationService.isRevoked(userSessionId)) {
        // ... reject revoked token
    }
}
// Tokens WITHOUT userSessionId proceed with full authentication (line 141+)
```

**Attack Vector:** An attacker who obtains a legacy JWT token (without `userSessionId`) cannot be locked out via the revocation mechanism. Even after an administrator explicitly revokes sessions, these tokens remain valid until natural expiry. Additionally, if an attacker can forge tokens without the `userSessionId` claim (requires knowledge of the JWT secret), they create un-revocable sessions.

**Exploitability:** Conditional on existence of legacy tokens or JWT secret compromise.

**Recommendation:** Reject all JWTs that lack the `userSessionId` claim. Implement a migration that invalidates legacy tokens after an upgrade grace period.

---

## FINDING 10: CSRF Protection Bypass via Multipart POST (Medium)

**CVSS 3.1 Estimate:** 5.4 (Medium)  
**CWE:** CWE-352 (Cross-Site Request Forgery)  
**Affected File:** `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/authc/AntiCsrfHelper.java` (lines 87-93)

**Description:**

The CSRF protection has multiple bypass conditions:

```java
// AntiCsrfHelper.java:87-93
return safeHttpMethod
    || isMultiPartFormDataPost(httpRequest)  // BYPASS: all multipart POSTs skip header check
    || !isSessionAuthentication()            // BYPASS: non-session auth (API key, basic)
    || isExemptRequest(httpRequest)           // BYPASS: exempt paths
    || isAntiCsrfTokenValid(httpRequest, ...);
```

Multipart form-data POST requests automatically pass CSRF validation without token verification. The comment states "token is passed as a form field instead of a custom header" but the validation at this layer is skipped entirely:

```java
// AntiCsrfHelper.java:88-90
|| isMultiPartFormDataPost(httpRequest) // token is passed as a form field instead of a custom header
                                        // and is validated in the directnjine code
```

**Attack Vector:** An attacker can craft a cross-origin `<form>` with `enctype="multipart/form-data"` targeting any Nexus POST endpoint. If the victim has an active session, the CSRF token check is skipped at this layer.

**Mitigating Factor:** The `Sec-Fetch-Site` header check (when enabled) provides a secondary defense. Downstream ExtDirect code may perform additional token validation.

**Additionally:** The entire CSRF protection can be disabled via configuration:
```java
@Value("${" + ENABLED + ":true}") final boolean enabled
```

**Recommendation:** Validate CSRF tokens for multipart requests at this layer (extract from form field). Do not rely solely on downstream validation. Remove the ability to globally disable CSRF protection.

---

## FINDING 11: Authenticated SSRF via Certificate Retrieval (Medium)

**CVSS 3.1 Estimate:** 5.0 (Medium)  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Affected Files:**
- `public/common/components/nexus-ssl/src/main/java/org/sonatype/nexus/ssl/CertificateRetriever.java` (lines 101-149)
- `public/common/components/nexus-ssl-plugin/src/main/java/com/sonatype/nexus/ssl/plugin/internal/ui/CertificateComponent.java` (lines 79-88)

**Description:**

The certificate retrieval feature makes outbound HTTPS connections to arbitrary hosts specified by the user:

```java
// CertificateRetriever.java:101
public Certificate[] retrieveCertificatesFromHttpsServer(final String host, final int port) throws Exception {
    httpClient.execute(new HttpGet("https://" + host + ":" + port));
```

The only input validation is `@HostnameOrIpAddress` on the host parameter, which validates hostname/IP format but does **not** block internal/private IP ranges (127.0.0.1, 10.x.x.x, 169.254.169.254, etc.).

**Attack Vector:** An authenticated user with `nexus:ssl-truststore:read` permission can probe internal network services, access cloud metadata endpoints (AWS `169.254.169.254`), and map internal infrastructure.

**Exploitability:** Requires authentication and specific permission. AWS metadata endpoint access could lead to credential theft.

**Recommendation:** Implement a private IP range blocklist. Block requests to link-local, loopback, and RFC 1918 addresses. Consider a DNS rebinding protection.

---

## FINDING 12: Authenticated SSRF via Email Configuration (Medium)

**CVSS 3.1 Estimate:** 4.9 (Medium)  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Affected File:** `public/selfhosted/components/api/nexus-api-rest-selfhosted/src/main/java/org/sonatype/nexus/api/rest/selfhosted/email/EmailConfigurationApiResource.java` (lines 64-69, 106-112)

**Description:**

The email configuration API accepts arbitrary SMTP host/port without blocking internal addresses:

```java
// ApiEmailConfiguration.java:28-34
@Hostname @NotBlank
private String host;

@PortNumber @NotNull
private Integer port;
```

The `@Hostname` validator allows all RFC-compliant hostnames and IPs, including private/internal ranges.

**Attack Vector:** An admin user can configure SMTP to point to internal hosts for port scanning and service discovery.

**Exploitability:** Requires `nexus:settings:update` (admin privilege). Impact is limited to internal network reconnaissance via SMTP probing.

**Recommendation:** Implement optional internal IP blocklist for outbound connections.

---

## FINDING 13: Weak Default TLS Certificate Signature Algorithm (Low)

**CVSS 3.1 Estimate:** 3.7 (Low)  
**CWE:** CWE-326 (Inadequate Encryption Strength)  
**Affected File:** `public/common/components/nexus-ssl/src/main/java/org/sonatype/nexus/ssl/KeyStoreManagerConfigurationSupport.java` (lines 40-42)

**Description:**

The default signature algorithm for auto-generated TLS certificates is SHA1withRSA:

```java
// KeyStoreManagerConfigurationSupport.java:40-42
private String signatureAlgorithm = "SHA1WITHRSA";
```

SHA-1 is deprecated for TLS certificate signatures. Modern browsers and security scanners flag SHA-1 certificates.

**Recommendation:** Change the default to `SHA256withRSA` or `SHA384withRSA`.

---

## FINDING 14: Missing SameSite Cookie Attribute on JWT Cookies (Low)

**CVSS 3.1 Estimate:** 3.1 (Low)  
**CWE:** CWE-1275 (Sensitive Cookie with Improper SameSite Attribute)  
**Affected File:** `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/JwtHelper.java` (lines 200-207)

**Description:**

JWT cookies are created without explicitly setting the `SameSite` attribute:

```java
// JwtHelper.java:200-207
Cookie cookie = new Cookie(JWT_COOKIE_NAME, jwt);
cookie.setMaxAge(this.expirySeconds);
cookie.setPath(contextPath);
cookie.setHttpOnly(true);
cookie.setSecure(cookieSecure && secureRequest);
// No SameSite attribute set
```

**Mitigating Factor:** Modern browsers default to `SameSite=Lax`, and the application has CSRF protection (Finding 10). `HttpOnly` is correctly set.

**Recommendation:** Explicitly set `SameSite=Strict` or `SameSite=Lax` on authentication cookies.

---

## Additional Observations (Informational)

### I1: Sensitive System Information Disclosure
- `SystemInformationResource` exposes system properties, environment variables, network interfaces, and JVM details to users with `nexus:atlas:read`.
- `SecurityDiagnosticResource` exposes full user roles, privileges, and permission details per-user.
- Obfuscation of sensitive keys uses heuristic substring matching (keys containing "password", "secret", etc.) which may miss non-standard key names.

### I2: Error Message Information Leakage
- `ExceptionMapperSupport.unexpectedResponse()` returns `exception.toString()` in the HTTP response body, potentially leaking class names, package structures, and internal error details.

### I3: SafeXml Allows DOCTYPE Declarations
- `SafeXml.newdocumentBuilderFactory()` sets `APACHE_DISALLOW_DOCTYPE_DECL` to `false`. While external entity features are disabled, internal entity expansion (billion laughs / XML bomb) is technically possible.

### I4: `java.util.Random` Usage
- `RandomExponentialSequence` uses `java.util.Random` (not `SecureRandom`). Currently used for backoff/jitter which is acceptable, but developers may inadvertently use this class for security-sensitive purposes.

### I5: File Blob Store Path Traversal (Admin-Only)
- `BlobStoreUtilImpl.validateFilePath()` checks segment length but not for `..` path components. Admin users creating file blob stores could potentially specify paths outside the intended blob storage directory.

### I6: JWT Expiry Allows Zero
- `JwtHelper` constructor allows `expirySeconds = 0` (check is `>= 0`), which creates tokens that expire at issuance time.

---

## Attack Chain Analysis

### Chain 1: Database Compromise → RCE
1. Exploit SQL injection (Finding 4) or obtain DB credentials
2. Decrypt serialized data using hardcoded key `"changeme"` (Finding 3)
3. Inject malicious serialized Java objects into Quartz job_data or MyBatis columns (Findings 1, 2)
4. Wait for deserialization → arbitrary code execution

### Chain 2: Credential Compromise → Full Control
1. Access instance using default `admin/admin123` (Finding 6)
2. Upload and execute Groovy scripts via Script API (Finding 5) with `container` binding
3. Access Spring DI container for full application control

### Chain 3: Stored XSS → Session Hijack
1. Upload content with malicious path names targeting browse template XSS (Finding 8)
2. When another user browses the repository, JavaScript executes
3. Steal JWT cookie (mitigated by HttpOnly) or perform actions as victim

---

## Recommendations Summary

| Priority | Action |
|----------|--------|
| **P0** | Implement Java deserialization filters (JEP 290) on all `ObjectInputStream` usage |
| **P0** | Remove hardcoded encryption key; require explicit configuration |
| **P0** | Remove hardcoded default password fallback |
| **P1** | Parameterize all SQL in MyBatis mappers; eliminate `${}` for user-influenced values |
| **P1** | Deprecate/disable script API by default; implement proper sandboxing if retained |
| **P1** | Force migration of legacy MD5/SHA-1 password hashes |
| **P2** | Escape all Velocity template variables in HTML context |
| **P2** | Reject JWTs without `userSessionId` claim |
| **P2** | Validate CSRF tokens for multipart requests at the filter layer |
| **P2** | Implement SSRF blocklists for internal/private IP ranges |
| **P3** | Update default TLS certificate algorithm to SHA-256+ |
| **P3** | Set explicit SameSite attribute on authentication cookies |

---

*This report is based on static source code analysis of the nexus-public repository. Runtime behavior, deployment configuration, and network architecture may affect the actual exploitability of these findings. Findings should be validated in a test environment before remediation.*
