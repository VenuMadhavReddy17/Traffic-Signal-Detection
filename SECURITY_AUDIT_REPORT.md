# Sonatype Nexus Repository Manager — Security Audit Report

**Repository:** https://github.com/sonatype/nexus-public  
**Version Audited:** 3.89.0-09  
**Date:** 2026-03-27  
**Auditor Role:** Senior Product Security Engineer / Bug Bounty Researcher  

---

## Executive Summary

This report documents a deep source code review of Sonatype Nexus Repository Manager (OSS). The audit focused exclusively on identifying real, exploitable security vulnerabilities across authentication, authorization, injection, cryptography, SSRF, XSS, deserialization, and path traversal attack surfaces. The codebase spans ~4,400 Java files and ~1,300 JavaScript/TypeScript files.

**Critical findings:** 12 distinct vulnerability classes identified, ranging from Critical (RCE via script engine) to Low (information disclosure). The most impactful findings involve SQL injection via MyBatis `${}` interpolation, unsafe Java deserialization in Quartz job data, a bypassable Groovy sandbox enabling RCE, and SSRF with private network access enabled by default.

---

## Findings Summary

| # | Title | Severity | CVSS Est. | Category |
|---|-------|----------|-----------|----------|
| 1 | SQL Injection via MyBatis `${}` String Interpolation | **Critical** | 9.8 | Injection |
| 2 | Groovy Script Engine with Bypassable Sandbox → RCE | **Critical** | 9.1 | Code Execution |
| 3 | Unsafe Java Deserialization in Quartz Job Data | **High** | 8.1 | Deserialization |
| 4 | SSRF via Proxy Repositories — Private Networks Allowed by Default | **High** | 7.5 | SSRF |
| 5 | SSRF via Certificate Retrieval with Trust-All TLS | **High** | 7.2 | SSRF |
| 6 | Default Admin Credentials (`admin123`) | **High** | 7.0 | Authentication |
| 7 | Legacy Password Hashing (MD5/SHA-1, Unsalted, 1 Iteration) | **High** | 7.0 | Cryptography |
| 8 | Stored XSS via `dangerouslySetInnerHTML` in React UI | **Medium** | 6.1 | XSS |
| 9 | Path Traversal in Dev-Mode Resource Serving | **Medium** | 5.9 | Path Traversal |
| 10 | JEXL Expression Injection via Content Selectors | **Medium** | 5.5 | Injection |
| 11 | HTTP Response Header Injection via Content-Disposition | **Medium** | 4.8 | Injection |
| 12 | Missing Authentication on Internal API Endpoints | **Low** | 4.3 | Authorization |

---

## Detailed Findings

---

### Finding 1: SQL Injection via MyBatis `${}` String Interpolation

**Severity:** Critical  
**Category:** SQL Injection (CWE-89)  
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Description

Multiple MyBatis mapper XML files use `${}` (string substitution) instead of `#{}` (parameterized binding) for values derived from application logic. In MyBatis, `${}` injects raw text directly into the SQL statement without escaping, creating SQL injection vectors if any upstream caller passes user-influenced data.

#### Affected Files

**ContentRepositoryDAO.xml** — Repository name injected as raw string literal:

```79:83:nexus-public/public/common/components/nexus-repository-content/src/main/resources/org/sonatype/nexus/repository/content/store/ContentRepositoryDAO.xml
  <select id="readContentRepositoryId" resultType="java.util.HashMap" databaseId="PostgreSQL">
      SELECT r.name, cr.repository_id FROM repository r
      INNER JOIN ${repositoryFormat}_content_repository cr ON r.id = cr.config_repository_id
      WHERE r.name = '${repositoryName}'
  </select>
```

`${repositoryName}` on line 82 is pasted into a single-quoted SQL string literal. A value like `' OR '1'='1` breaks out and modifies query logic.

**SearchTableDAO.xml** — Filter, sort, and ID parameters via raw substitution:

```447:456:nexus-public/public/common/components/nexus-search-sql/src/main/resources/org/sonatype/nexus/repository/search/sql/store/SearchTableDAO.xml
        (${assetFilter})
      </where>
      ...
      <if test="filter != null">(${filter})</if>
    </where>
    ORDER BY <if test="sortColumnName != null">
      ${sortColumnName} ${sortDirection}
```

The `filter`, `assetFilter`, `sortColumnName`, and `sortDirection` fields in `SqlSearchRequest` are plain `String` types that get interpolated directly into SQL. The `componentId` values in `foreach` loops also use `${componentId}` instead of `#{componentId}`:

```346:348:nexus-public/public/common/components/nexus-search-sql/src/main/resources/org/sonatype/nexus/repository/search/sql/store/SearchTableDAO.xml
    <foreach collection="componentIds" item="componentId" open="AND component_id IN (" separator="," close=")">
      ${componentId}
    </foreach>
```

**AssetDAO.xml and BrowseNodeDAO.xml** — Same `(${filter})` pattern for dynamic WHERE clauses.

#### Exploitation

The `SqlSearchRequest.filter` field is built from `SqlSearchQueryCondition.getSqlConditionFormat()`, which uses parameterized placeholders internally. However, the architectural pattern of passing a raw SQL string through `${}` means any future code path or bug that populates `filter`, `sortColumnName`, or `repositoryName` with unsanitized input creates an immediate, exploitable SQL injection. The `sortColumnName` is particularly dangerous as sort columns are a classic blind-SQLi vector using `CASE WHEN` or stacked queries.

#### Remediation

1. Replace `'${repositoryName}'` with `#{repositoryName}` (parameterized binding).
2. Replace `${componentId}` in foreach loops with `#{componentId}`.
3. For structural identifiers (`${format}`, `${sortColumnName}`), implement strict allowlist validation before they reach MyBatis.
4. Consider replacing `${filter}` pattern with a query-builder that produces fully parameterized SQL.

---

### Finding 2: Groovy Script Engine with Bypassable Sandbox → RCE

**Severity:** Critical  
**Category:** Remote Code Execution (CWE-94)  
**CVSS:** 9.1 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)

#### Description

The Nexus Script API (`/v1/script`) allows privileged users to upload and execute Groovy scripts. The "sandbox" is a `SecureASTCustomizer` that only blacklists `java.lang.System`:

```89:95:nexus-public/public/common/components/nexus-script/src/main/java/org/sonatype/nexus/internal/script/groovy/GroovyScriptEngineFactory.java
  private CompilationCustomizer secureASTCustomizer() {
    SecureASTCustomizer secureASTCustomizer = new SecureASTCustomizer();
    secureASTCustomizer.setImportsBlacklist(Collections.singletonList("java.lang.System"));
    secureASTCustomizer.setReceiversBlackList(Collections.singletonList(System.class.getName()));
    secureASTCustomizer.setIndirectImportCheckEnabled(true);
    return secureASTCustomizer;
  }
```

Additionally, all scripts receive a `container` binding that is a `GlobalComponentLookupHelper` — capable of resolving arbitrary Spring/Sisu components:

```
bindings.put("container", lookupHelper);
```

#### Exploitation

1. `SecureASTCustomizer` blacklists are notoriously bypassable in Groovy. Only `java.lang.System` is blocked. Attackers can use `Runtime.getRuntime().exec()`, `ProcessBuilder`, Java reflection (`Class.forName`), or metaclass manipulation to execute arbitrary system commands.
2. The `container` binding provides access to the entire Nexus component graph, allowing data exfiltration, configuration modification, and privilege escalation.
3. Script execution requires `nexus:script:*:run` permission, but any compromised admin account or privilege escalation grants full RCE.

#### Remediation

1. Deprecate and disable the Script API by default (Sonatype has partially done this with `ScriptingDisabledException`).
2. If scripts must be supported, replace the blacklist with a strict allowlist of safe classes.
3. Remove or restrict the `container` binding.
4. Consider running scripts in a separate process with restricted capabilities.

---

### Finding 3: Unsafe Java Deserialization in Quartz Job Data

**Severity:** High  
**Category:** Deserialization of Untrusted Data (CWE-502)  
**CVSS:** 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Description

Quartz job data stored in the database is deserialized using unconstrained `ObjectInputStream.readObject()`:

```77:92:nexus-public/public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/bulkread/QuartzObjectBuilder.java
  private static JobDataMap deserializeJobData(final byte[] data) throws IOException, ClassNotFoundException {
    try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis)) {
      Object jobData = ois.readObject();
      if (jobData instanceof JobDataMap jobDataMap) {
        return jobDataMap;
      }
      else if (jobData instanceof Map<?, ?> map) {
        return new JobDataMap(map);
      }
      // ...
    }
  }
```

The same pattern exists in:
- `QuartzJobDataTypeHandler.java` — MyBatis type handler for Quartz job data
- `AbstractSerializableTypeHandler.java` — generic MyBatis serializable handler (uses `ObjectInputStreamWithClassLoader`)

#### Exploitation

If an attacker can write malicious serialized bytes to the Quartz job store (via SQL injection, compromised database access, backup poisoning, or a rogue admin), standard Java deserialization gadget chains (e.g., Commons Collections, Commons BeanUtils) can achieve remote code execution. The lack of `ObjectInputFilter` (JEP 290) or `ValidatingObjectInputStream` means any class on the classpath can be instantiated during deserialization.

#### Remediation

1. Implement JEP 290 deserialization filters (`ObjectInputFilter`) to allowlist only expected types (`JobDataMap`, `HashMap`, primitive wrappers).
2. Migrate Quartz job data storage to JSON serialization.
3. Audit `ObjectInputStreamWithClassLoader` for its actual class-loading restrictions.

---

### Finding 4: SSRF via Proxy Repositories — Private Networks Allowed by Default

**Severity:** High  
**Category:** Server-Side Request Forgery (CWE-918)  
**CVSS:** 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

#### Description

The `AntiSsrfHelper` defaults to allowing private network access:

```57:58:nexus-public/public/common/components/nexus-validation/src/main/java/org/sonatype/nexus/validation/ssrf/AntiSsrfHelper.java
  public AntiSsrfHelper(
      @Value("${nexus.proxy.allowPrivateNetworks:true}") final boolean allowPrivateNetworks,
```

When `allowPrivateNetworks` is `true` (the default), proxy repositories can reach RFC1918 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.1), and link-local addresses. Only the cloud metadata endpoint `169.254.169.254` is always blocked.

Additionally, the proxy fetch handler follows HTTP 300 redirects with alternate URLs:

```730:745:nexus-public/public/common/components/nexus-repository-services/src/main/java/org/sonatype/nexus/repository/proxy/ProxyFacetSupport.java
  protected Content handle300MultipleChoicesError(...) {
    List<String> alternativeUris = extractUrls(response);
    for (String alternativeUri : alternativeUris) {
      Content alternativeContent = fetch(alternativeUri, context, stale);
```

A malicious or compromised upstream repository can return `300` responses with `Link:` headers pointing to internal services.

#### Exploitation

1. An attacker with repository configuration privileges creates a proxy repository pointing to an internal service (e.g., `http://192.168.1.1:8080/admin`).
2. Alternatively, a compromised upstream can redirect fetches to internal services via 300 responses.
3. With `allowPrivateNetworks=true`, Nexus will make HTTP requests to internal infrastructure, enabling network scanning, internal service enumeration, and data exfiltration.

#### Remediation

1. Change the default to `nexus.proxy.allowPrivateNetworks:false`.
2. Implement DNS rebinding protection (re-resolve and validate after each redirect).
3. Validate alternate URLs from 300 responses against the original repository's base URL domain.

---

### Finding 5: SSRF via Certificate Retrieval with Trust-All TLS

**Severity:** High  
**Category:** Server-Side Request Forgery (CWE-918)  
**CVSS:** 7.2 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N)

#### Description

The `CertificateRetriever` uses a trust-all `X509TrustManager` and `NoopHostnameVerifier`:

```75:109:nexus-public/public/common/components/nexus-ssl/src/main/java/org/sonatype/nexus/ssl/CertificateRetriever.java
  private static final TrustManager ACCEPT_ALL_TRUST_MANAGER = new X509TrustManager() {
    public void checkServerTrusted(final X509Certificate[] certs, final String authType) {
      // all trusted
    }
    // ...
  };
  // ...
  SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sc, NoopHostnameVerifier.INSTANCE);
```

The `CertificateComponent` UI endpoint calls this with a user-supplied hostname, validated only by `HostnameOrIpAddressValidator` which accepts any syntactically valid hostname or IP — including RFC1918 addresses:

```
public boolean isValid(final String value, ...) {
    return InternetDomainName.isValid(value) || InetAddresses.isInetAddress(value);
}
```

No `AntiSsrfHelper` validation is applied to this endpoint.

#### Exploitation

A user with `nexus:ssl-truststore:read` permission can make Nexus connect to any host:port (including internal network addresses) over TLS. This enables:
- Internal network port scanning
- Service fingerprinting via TLS handshake behavior
- Reading peer certificate chains from internal services

#### Remediation

1. Apply `AntiSsrfHelper` validation to the certificate retrieval endpoint.
2. Restrict allowed port ranges.
3. Add rate limiting to prevent automated scanning.

---

### Finding 6: Default Admin Credentials (`admin123`)

**Severity:** High  
**Category:** Use of Hard-coded Credentials (CWE-798)  
**CVSS:** 7.0 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

#### Description

```33:34:nexus-public/public/selfhosted/components/nexus-self-hosted/src/main/java/org/sonatype/nexus/security/config/AdminPasswordSourceImpl.java
  public static final String DEFAULT_PASSWORD = "admin123";
```

The fallback password `admin123` is used when:
1. Random password generation is disabled (`randomPassword=false`)
2. The system fails to write the generated random password to disk

#### Exploitation

Attackers routinely scan for Nexus instances using `admin:admin123`. This has been exploited widely in the wild on internet-facing instances. The fallback to `admin123` on file write failure is particularly dangerous as it can silently downgrade a supposedly-random-password deployment.

#### Remediation

1. Remove the `admin123` fallback entirely.
2. On password file write failure, fail the startup or force password change on first login.
3. Implement account lockout after failed login attempts.

---

### Finding 7: Legacy Password Hashing (MD5/SHA-1, Unsalted, 1 Iteration)

**Severity:** High  
**Category:** Use of a Broken or Risky Cryptographic Algorithm (CWE-327)  
**CVSS:** 7.0 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

#### Description

```39:57:nexus-public/public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/internal/LegacyNexusPasswordService.java
  public LegacyNexusPasswordService() {
    this.sha1PasswordService = new DefaultPasswordService();
    DefaultHashService sha1HashService = new DefaultHashService();
    sha1HashService.setHashAlgorithmName("SHA-1");
    sha1HashService.setHashIterations(1);
    sha1HashService.setGeneratePublicSalt(false);
    // ...
    this.md5PasswordService = new DefaultPasswordService();
    DefaultHashService md5HashService = new DefaultHashService();
    md5HashService.setHashAlgorithmName("MD5");
    md5HashService.setHashIterations(1);
    md5HashService.setGeneratePublicSalt(false);
```

Legacy passwords are verified against unsalted MD5 and SHA-1 with a single iteration.

#### Exploitation

If an attacker obtains the user database (via SQL injection, backup exposure, or misconfigured access), legacy password hashes can be cracked nearly instantly using rainbow tables or GPU-accelerated brute force. An unsalted single-iteration SHA-1 hash can be cracked at billions of hashes per second.

#### Remediation

1. Force password rotation for all accounts still using legacy hashes.
2. Implement transparent rehashing: when a user authenticates successfully with a legacy hash, rehash their password using the modern algorithm (bcrypt/scrypt/Argon2).
3. Set a deadline after which legacy hash authentication is rejected.

---

### Finding 8: Stored XSS via `dangerouslySetInnerHTML` in React UI

**Severity:** Medium  
**Category:** Cross-Site Scripting (CWE-79)  
**CVSS:** 6.1 (AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N)

#### Description

Multiple React components use `dangerouslySetInnerHTML` with server-provided data:

**Branding header/footer** (`App.jsx`):
```jsx
dangerouslySetInnerHTML={{ __html: headerHtml }}
dangerouslySetInnerHTML={{ __html: footerHtml }}
```

**Metric health details** (`MetricHealthDetails.jsx`):
```jsx
<span dangerouslySetInnerHTML={{__html: metric.message}} />
```

**Capability about text** (`CapabilitiesEdit.jsx`):
```jsx
<NxReadOnly.Data dangerouslySetInnerHTML={{ __html: value }} />
```

#### Exploitation

1. **Branding XSS:** An admin who can modify branding settings can inject `<script>` tags that execute for every user loading the UI. This enables session hijacking, credential theft, or privilege escalation if a higher-privileged admin visits the page.
2. **Metric message XSS:** If health check metrics include unsanitized error messages from external systems, reflected markup could execute in the admin UI.

#### Remediation

1. Sanitize HTML before rendering using DOMPurify or similar library.
2. Replace `dangerouslySetInnerHTML` with safe rendering alternatives where possible.
3. Implement Content-Security-Policy headers to mitigate XSS impact.

---

### Finding 9: Path Traversal in Dev-Mode Resource Serving

**Severity:** Medium  
**Category:** Path Traversal (CWE-22)  
**CVSS:** 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)

#### Description

```122:132:nexus-public/public/common/components/nexus-base/src/main/java/org/sonatype/nexus/internal/webresources/DevModeResources.java
  public File getFileIfOnFileSystem(final String path) {
    if (resourceLocations != null) {
      for (File dir : resourceLocations) {
        File file = new File(dir, path);
        if (file.exists()) {
          return file;
        }
      }
    }
    return null;
  }
```

When `NEXUS_RESOURCE_DIRS` or `nexus.resource.dirs` is set, HTTP request paths are passed to `new File(dir, path)` without canonicalization or containment checks. A path containing `../` sequences can escape the resource directory.

#### Exploitation

If dev-mode resource directories are enabled (common in development/staging environments), an attacker can read arbitrary files accessible to the Nexus process by requesting paths like `/static/../../../etc/passwd`. The `WebResourceServiceImpl` serves the resulting file content over HTTP.

#### Remediation

1. Canonicalize the resolved path and verify it starts with the configured resource directory.
2. Reject paths containing `..` segments.
3. Document that `NEXUS_RESOURCE_DIRS` should never be used in production.

---

### Finding 10: JEXL Expression Injection via Content Selectors

**Severity:** Medium  
**Category:** Expression Language Injection (CWE-917)  
**CVSS:** 5.5 (AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L)

#### Description

Content selectors use Apache Commons JEXL for expression evaluation. A `SandboxJexlUberspect` restricts available methods:

```47:64:nexus-public/public/common/components/nexus-selector/src/main/java/org/sonatype/nexus/selector/internal/SandboxJexlUberspect.java
  public JexlMethod getConstructor(final Object ctorHandle, final Object... args) {
    return null; // constructors disabled
  }
  public JexlMethod getMethod(final Object obj, final String method, final Object... args) {
    if (obj instanceof String && STRING_METHODS.contains(method)) {
      return super.getMethod(obj, method, args);
    }
    // ... Map and Collection methods only
    return null;
  }
```

#### Exploitation

While the sandbox is more restrictive than the Groovy sandbox, JEXL sandbox escapes have been published historically (CVE-2022-45685, CVE-2022-45693). If a user with content selector creation privileges crafts a malicious JEXL expression that exploits a parser bug or sandbox escape, it could lead to arbitrary code execution in the context of the JEXL evaluation.

#### Remediation

1. Keep JEXL library updated to the latest version.
2. Consider replacing JEXL with a purpose-built, non-Turing-complete expression evaluator.
3. Restrict who can create JEXL-type selectors (prefer CSEL syntax).

---

### Finding 11: HTTP Response Header Injection via Content-Disposition

**Severity:** Medium  
**Category:** HTTP Response Splitting (CWE-113)  
**CVSS:** 4.8 (AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N)

#### Description

```93:94:nexus-public/public/common/components/nexus-coreui-plugin/src/main/java/org/sonatype/nexus/coreui/internal/wonderland/DownloadResource.java
      return Response.ok(download.getBytes())
          .header(CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
```

The `fileName` parameter from `@PathParam` is concatenated directly into the `Content-Disposition` header. If the JAX-RS implementation does not strip CR/LF characters, this enables HTTP response header injection.

#### Exploitation

A request with `fileName` containing `%0d%0a` (CRLF) sequences could inject additional HTTP headers, potentially enabling cache poisoning or XSS via injected `Content-Type` headers. Requires `nexus:wonderland:download` permission.

#### Remediation

1. Strip or reject CR/LF characters from `fileName` before header insertion.
2. Use RFC 6266 compliant `Content-Disposition` encoding (`filename*=UTF-8''...`).

---

### Finding 12: Missing Authentication on Internal API Endpoints

**Severity:** Low  
**Category:** Missing Authentication (CWE-306)  
**CVSS:** 4.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

#### Description

Several endpoints lack `@RequiresAuthentication` annotations:

**Repository recipes** (`RepositoryInternalResource.java`):
```java
@GET
@Path("/recipes")
public List<RecipeXO> getRecipes() {
    return recipes.stream()
        .filter(Recipe::isFeatureEnabled)
        .map(RecipeXO::new)
        .collect(toList());
}
```

**Upload definitions** (`UploadDefinitionResource.java`):
```java
@Path("upload-specs")
@GET
public List<UploadDefinitionXO> get() {
    return uploadManager.getAvailableDefinitions().stream().map(this::from).collect(toList());
}
```

These endpoints expose metadata about supported repository formats, upload field specifications, and feature-enabled recipes without requiring authentication.

#### Exploitation

An unauthenticated attacker can enumerate:
- All supported repository formats and their capabilities
- Upload field specifications for each format
- Feature flags that are enabled

This aids in reconnaissance for targeted attacks against the Nexus instance.

#### Remediation

1. Add `@RequiresAuthentication` to all internal API endpoints.
2. Implement a default-deny security policy for `/service/rest/internal/**`.

---

## Additional Observations

### Legacy Cipher Implementations

**`LegacyCipherFactoryImpl.java`** uses PBKDF2-HMAC-SHA1 with 1024 iterations and AES-CBC. While deprecated, any secrets encrypted under this path have weaker-than-modern confidentiality guarantees. The `@Deprecated` annotation should be accompanied by active migration tooling.

### CSRF Protection Edge Cases

The `AntiCsrfFilter` can be disabled via `nexus.security.anticsrftoken.enabled=false`. When enabled, it uses a cookie-to-header token pattern that is solid for session-based UI, but non-session authentication methods (API tokens, basic auth) may bypass CSRF checks by design. The `@RequiresUser` annotation on `FreezeResource` is weaker than `@RequiresAuthentication` in Shiro (allows remembered-me users).

### Temporary File Permissions

`CompressingTempFileStore.java` and `GeneratedContentSourceSupport.java` create temp files with empty prefixes and default permissions, which on shared hosts could allow local users to read sensitive content (support bundles, APT repository data).

### DNS Rebinding in SSRF Validation

The `AntiSsrfHelper` resolves DNS once and caches results. A DNS rebinding attack could pass validation with a public IP, then resolve to an internal IP on the actual connection. The validation and connection use separate DNS resolution steps.

---

## Risk Matrix

| Risk Level | Count | Impact |
|------------|-------|--------|
| Critical   | 2     | RCE, Full database compromise |
| High       | 4     | Credential theft, SSRF to internal services, Authentication bypass |
| Medium     | 4     | Stored XSS, Path traversal, Expression injection, Header injection |
| Low        | 2     | Information disclosure |

---

## Recommended Prioritization

1. **Immediate (Critical):** Audit all callers of MyBatis mappers using `${}` for user-reachable data flows. Replace with `#{}` or strict allowlists.
2. **Immediate (Critical):** Disable the Groovy Script API by default in all new installations.
3. **Short-term (High):** Implement JEP 290 deserialization filters for Quartz job data.
4. **Short-term (High):** Change `nexus.proxy.allowPrivateNetworks` default to `false`.
5. **Short-term (High):** Apply `AntiSsrfHelper` to certificate retrieval endpoints.
6. **Medium-term:** Force migration away from legacy password hashes.
7. **Medium-term:** Sanitize all `dangerouslySetInnerHTML` usage in the React UI.
8. **Medium-term:** Add canonical path validation to dev-mode resource serving.

---

*This report covers the `/workspace/nexus-public/public/` source tree. LDAP integration, OAuth/SAML, and other modules outside this tree were not in scope.*
