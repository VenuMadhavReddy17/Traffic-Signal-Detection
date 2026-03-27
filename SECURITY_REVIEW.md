# Security Code Review: sentry-rust SDK

**Repository:** https://github.com/getsentry/sentry-rust  
**Review Date:** 2026-03-27  
**Reviewer Role:** Senior Product Security Engineer / Bug Bounty Researcher  
**Scope:** Full source code review of all Rust crates in the workspace  
**Methodology:** Manual code review focused on exploitable vulnerabilities with code-level evidence

---

## Executive Summary

After a thorough source code review of the `sentry-rust` SDK, I identified **3 confirmed vulnerabilities** and **2 items that are valid but intentional design trade-offs**. The findings primarily concern information disclosure of secret material through logging/formatting paths and an environment-variable-controlled TLS bypass.

The codebase is generally well-engineered with appropriate use of Rust's type system and safety mechanisms. The `unsafe` code blocks are limited and mostly sound. The concurrency patterns use standard `Arc<Mutex<>>` / `RwLock` idioms with appropriate ordering.

---

## Finding 1: DSN Secret Key Disclosed via `Dsn::Display` in Debug Logging

**Verdict: Valid Vulnerability**

| Attribute | Value |
|-----------|-------|
| **File** | `sentry-types/src/dsn.rs` |
| **Function** | `impl fmt::Display for Dsn` |
| **Lines** | 148-161 |
| **CWE** | CWE-532: Insertion of Sensitive Information into Log File |
| **Impact** | Confidentiality |
| **Severity** | Low-Medium (requires `debug: true` opt-in) |

### Code Evidence

The `Dsn::Display` implementation includes the `secret_key` in its output without any redaction:

```rust
// sentry-types/src/dsn.rs, lines 148-161
impl fmt::Display for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}://{}:", self.scheme, self.public_key)?;
        if let Some(ref secret_key) = self.secret_key {
            write!(f, "{secret_key}")?;  // <-- Secret key written to output
        }
        write!(f, "@{}", self.host)?;
        if let Some(ref port) = self.port {
            write!(f, ":{port}")?;
        }
        write!(f, "{}{}", self.path, self.project_id)?;
        Ok(())
    }
}
```

This `Display` output is then used in initialization logging:

```rust
// sentry/src/init.rs, line 109
if let Some(dsn) = client.dsn() {
    sentry_debug!("enabled sentry client for DSN {}", dsn);  // <-- Calls Dsn::Display
}
```

The `sentry_debug!` macro writes to stderr when `debug: true`:

```rust
// sentry-core/src/macros.rs, lines 56-65
macro_rules! sentry_debug {
    ($($arg:tt)*) => {
        $crate::Hub::with(|hub| {
            if hub.client().map_or(false, |c| c.options().debug) {
                eprint!("[sentry] ");
                eprintln!($($arg)*);  // <-- Writes to stderr
            }
        });
    }
}
```

Additionally, `Dsn` uses `#[derive(Debug)]` (line 65), so `{:?}` formatting also exposes all fields including `secret_key`. This is propagated through `ClientOptions::Debug` (line 242 of `clientoptions.rs`) and `Client::Debug`, meaning any debug-formatting of the client or its options exposes the secret.

### Root Cause

The `Dsn` type's `Display` and `Debug` implementations do not redact the `secret_key` field. When debug logging is enabled (a common configuration during development that can accidentally persist into production), the complete DSN including the secret key is written to stderr.

### Exploitation Scenario

1. A developer enables `debug: true` in their `ClientOptions` during development
2. The application is deployed to production with debug still enabled (or debug is enabled in production for troubleshooting)
3. The `sentry::init()` function logs `"enabled sentry client for DSN https://publickey:SECRETKEY@sentry.io/1234"` to stderr
4. Stderr output is captured by a log aggregation system (e.g., CloudWatch, Datadog, ELK stack)
5. An attacker with read access to logs (e.g., junior developer, compromised monitoring account) obtains the DSN secret key
6. With legacy DSN authentication, the secret key provides elevated write access to the Sentry project

### Impact

- **Confidentiality:** The DSN secret key is exposed to any entity with access to stderr/log output
- In legacy Sentry configurations, the secret key provides write access to the project (event submission, management)

---

## Finding 2: Curl Transport Unconditionally Enables Verbose Mode, Logging Auth Headers

**Verdict: Valid Vulnerability**

| Attribute | Value |
|-----------|-------|
| **File** | `sentry/src/transports/curl.rs` |
| **Function** | `CurlHttpTransport::new_internal` |
| **Lines** | 80-91 |
| **CWE** | CWE-532: Insertion of Sensitive Information into Log File |
| **Impact** | Confidentiality |
| **Severity** | Low-Medium (requires `debug: true` opt-in) |

### Code Evidence

The curl transport **unconditionally** enables verbose mode on the HTTP handle:

```rust
// sentry/src/transports/curl.rs, lines 71-91
headers.append(&format!("X-Sentry-Auth: {auth}")).unwrap();  // auth contains secret
headers.append("Expect:").unwrap();
handle.http_headers(headers).unwrap();
handle.upload(true).unwrap();
handle.in_filesize(body.get_ref().len() as u64).unwrap();
handle
    .read_function(move |buf| Ok(body.read(buf).unwrap_or(0)))
    .unwrap();
handle.verbose(true).unwrap();  // <-- ALWAYS enabled, not conditional on debug
handle
    .debug_function(move |info, data| {
        let prefix = match info {
            curl::easy::InfoType::HeaderIn => "< ",
            curl::easy::InfoType::HeaderOut => "> ",  // <-- Outbound headers logged
            curl::easy::InfoType::DataOut => "",
            _ => return,
        };
        sentry_debug!("curl: {}{}", prefix, String::from_utf8_lossy(data).trim());
    })
    .unwrap();
```

The `auth` variable is constructed from `Dsn::to_auth().to_string()`, which via `Auth::Display` includes `sentry_secret` when present:

```rust
// sentry-types/src/auth.rs, lines 130-148
impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sentry sentry_key={}, sentry_version={}", self.key, self.version)?;
        // ...
        if let Some(ref secret) = self.secret {
            write!(f, ", sentry_secret={secret}")?;  // <-- Secret included in auth header
        }
        Ok(())
    }
}
```

### Root Cause

`handle.verbose(true)` is called unconditionally on every HTTP request, not gated behind the debug flag. While the `sentry_debug!` call inside the debug callback only prints when `debug: true`, curl still invokes the callback for every request (performance overhead) and the auth header content—including `sentry_secret`—is passed to the callback. When debug mode is on, the full `X-Sentry-Auth` header including `sentry_secret` is written to stderr.

### Exploitation Scenario

1. Application uses the `curl` transport feature and has `debug: true` enabled
2. Every HTTP request to Sentry logs the full outbound headers to stderr via `sentry_debug!`
3. The `X-Sentry-Auth` header value (e.g., `Sentry sentry_key=abc123, sentry_version=7, sentry_secret=SECRET456`) appears in stderr
4. An attacker with log access obtains the auth credentials

### Impact

- **Confidentiality:** Sentry authentication credentials (public key + secret key) are logged on every request when debug is enabled
- Even when debug is off, `handle.verbose(true)` causes unnecessary processing overhead in curl for every request

---

## Finding 3: TLS Certificate Validation Bypass via Environment Variable

**Verdict: Valid Vulnerability (Intentional Feature with Security Risk)**

| Attribute | Value |
|-----------|-------|
| **File** | `sentry/src/defaults.rs` |
| **Function** | `apply_defaults` |
| **Lines** | 112-114 |
| **CWE** | CWE-295: Improper Certificate Validation |
| **Impact** | Confidentiality, Integrity |
| **Severity** | Medium (requires environment variable control) |

### Code Evidence

The `SSL_VERIFY` environment variable can disable TLS certificate validation:

```rust
// sentry/src/defaults.rs, lines 112-114
if let Ok(accept_invalid_certs) = std::env::var("SSL_VERIFY") {
    opts.accept_invalid_certs = !accept_invalid_certs.parse().unwrap_or(true);
}
```

The logic: `SSL_VERIFY=false` → `parse::<bool>()` returns `Ok(false)` → `!false = true` → certificate validation is disabled.

This propagates to all transport implementations:

**Reqwest** (`sentry/src/transports/reqwest.rs`, line 35-37):
```rust
if options.accept_invalid_certs {
    builder = builder.danger_accept_invalid_certs(true);
}
```

**Curl** (`sentry/src/transports/curl.rs`, lines 46-49):
```rust
if accept_invalid_certs {
    handle.ssl_verify_host(false).unwrap();
    handle.ssl_verify_peer(false).unwrap();
}
```

**Ureq** (`sentry/src/transports/ureq.rs`, line 42):
```rust
.disable_verification(options.accept_invalid_certs)
```

### Root Cause

A single environment variable (`SSL_VERIFY`) can silently disable all TLS certificate validation for Sentry SDK communications across all transport backends. There is no logging or warning when this occurs (the `accept_invalid_certs` field is printed in `ClientOptions::Debug` but only if debug formatting is actively used).

### Exploitation Scenario

1. An attacker with access to the deployment environment (e.g., shared hosting, CI/CD pipeline, container orchestration) sets `SSL_VERIFY=false`
2. The Sentry SDK initializes and `apply_defaults()` reads the environment variable, disabling certificate validation
3. The attacker performs a man-in-the-middle attack on the network path between the application and Sentry's API
4. The attacker intercepts all telemetry data sent to Sentry, which may include: stack traces with source code paths, error messages containing user data, request bodies, PII (if `send_default_pii` is enabled), session data, breadcrumbs with user actions
5. The attacker can also modify or drop events in transit

### Impact

- **Confidentiality:** All telemetry data (potentially containing PII, source code paths, error details) can be intercepted
- **Integrity:** Events can be modified or dropped by a MITM attacker
- Note: The `accept_invalid_certs` option is documented with a warning, but the env-var path has no runtime warning

---

## Finding 4: Sensitive Header Filter List is Incomplete

**Verdict: Not a confirmed vulnerability (defense-in-depth concern)**

| Attribute | Value |
|-----------|-------|
| **File** | `sentry-core/src/utils.rs` |
| **Function** | `is_sensitive_header` |
| **Lines** | 3-18 |
| **CWE** | N/A |
| **Impact** | Potential Confidentiality (context-dependent) |

### Code Evidence

```rust
// sentry-core/src/utils.rs, lines 3-18
const SENSITIVE_HEADERS_UPPERCASE: &[&str] = &[
    "AUTHORIZATION",
    "PROXY_AUTHORIZATION",
    "COOKIE",
    "SET_COOKIE",
    "X_FORWARDED_FOR",
    "X_REAL_IP",
    "X_API_KEY",
];
```

This list is used to filter headers in Tower and Actix integrations when `send_default_pii` is false. The list covers the most common sensitive headers but omits some that may carry sensitive data in certain applications (e.g., custom session tokens, CSRF tokens). However, the list is a reasonable default and applications can use `before_send` callbacks to implement custom filtering.

### Verdict

Not a confirmed vulnerability. The existing list covers standard sensitive headers, and the SDK provides mechanisms (`before_send`, `before_breadcrumb`) for applications to implement custom filtering for non-standard sensitive headers.

---

## Finding 5: `transmute` of `ThreadId` to `u64` (Unsound but Not Exploitable)

**Verdict: Not a vulnerability**

| Attribute | Value |
|-----------|-------|
| **File** | `sentry-backtrace/src/integration.rs` |
| **Function** | `current_thread` |
| **Line** | 97 |

### Code Evidence

```rust
// sentry-backtrace/src/integration.rs, line 97
let thread_id: u64 = unsafe { std::mem::transmute(thread::current().id()) };
```

This `transmute` relies on `ThreadId` having the same layout as `u64`. Currently `ThreadId` is internally a `NonZeroU64`, making this work in practice. If the standard library changes `ThreadId`'s layout to a different 8-byte representation, the transmute would produce an incorrect but non-exploitable thread ID. If the size changes, it would be a compile-time error.

### Verdict

Not a security vulnerability. This is a code quality/soundness concern that would produce incorrect (but harmless) thread IDs or a compile error if the `ThreadId` representation changes. The comment in the code acknowledges this is a workaround for `as_u64()` being nightly-only.

---

## Finding 6: `release_name!` Macro Uses `static mut` with `transmute`

**Verdict: Not a vulnerability**

| Attribute | Value |
|-----------|-------|
| **File** | `sentry-core/src/macros.rs` |
| **Function** | `release_name!` macro |
| **Lines** | 17-35 |

### Code Evidence

```rust
// sentry-core/src/macros.rs, lines 17-35
macro_rules! release_name {
    () => {{
        use std::sync::Once;
        static mut INIT: Once = Once::new();
        static mut RELEASE: Option<String> = None;
        unsafe {
            INIT.call_once(|| {
                RELEASE = option_env!("CARGO_PKG_NAME").and_then(|name| {
                    option_env!("CARGO_PKG_VERSION").map(|version| format!("{}@{}", name, version))
                });
            });
            RELEASE.as_ref().map(|x| {
                let release: &'static str = ::std::mem::transmute(x.as_str());
                ::std::borrow::Cow::Borrowed(release)
            })
        }
    }};
}
```

### Verdict

Not a security vulnerability. The `Once::call_once` ensures the `static mut RELEASE` is written exactly once and is immutable afterward. The `transmute` to `&'static str` is valid because the `String` lives in a static variable with `'static` lifetime. While the `static mut` pattern is deprecated in favor of `OnceLock`/`LazyLock`, the current usage is sound.

---

## Reviewed Areas with No Findings

The following areas were reviewed and found to have no exploitable vulnerabilities:

- **DSN URL parsing** (`sentry-types/src/dsn.rs`): Uses the well-tested `url` crate; input validation is adequate with proper error types
- **API URL construction** (`Dsn::api_url`): Inputs come from already-validated DSN fields; `Url::parse` provides final validation
- **Rate limiter parsing** (`sentry/src/transports/ratelimit.rs`): Header parsing uses safe string operations; invalid values default to 60-second backoff
- **Hub thread-local safety** (`sentry-core/src/hub_impl.rs`): `UnsafeCell` access is properly guarded by thread-local semantics; `SwitchGuard` is correctly `!Send`
- **Pin projection in `SentryFuture`** (`sentry-core/src/futures.rs`): Structural pinning invariant is maintained; `hub` field is `Clone` and doesn't require pinning
- **macOS `sysctlbyname` FFI** (`sentry-contexts/src/utils.rs`): Proper two-pass size query pattern; buffer allocation matches reported size
- **Transport queue** (`sentry/src/transports/thread.rs`): Bounded channel (30) provides backpressure; envelope drops are logged
- **Concurrency primitives**: Lock ordering is consistent (span → transaction); `PoisonError::into_inner` is used to recover from panicked threads
- **PII scrubbing** (`sentry-core/src/utils.rs`): URL username/password are properly redacted; sensitive headers are filtered in Tower/Actix integrations
- **Envelope parsing** (`sentry-types/src/protocol/envelope.rs`): No unbounded allocations from untrusted input in the SDK's parsing paths

---

## Summary Table

| # | Finding | File | Line(s) | Verdict | CWE | Severity |
|---|---------|------|---------|---------|-----|----------|
| 1 | DSN secret key in Display/Debug + debug logging | `sentry-types/src/dsn.rs`, `sentry/src/init.rs` | 148-161, 109 | **Valid vulnerability** | CWE-532 | Low-Medium |
| 2 | Curl verbose mode logs auth headers | `sentry/src/transports/curl.rs` | 80-91 | **Valid vulnerability** | CWE-532 | Low-Medium |
| 3 | TLS bypass via `SSL_VERIFY` env var | `sentry/src/defaults.rs` | 112-114 | **Valid vulnerability** (intentional feature) | CWE-295 | Medium |
| 4 | Incomplete sensitive header list | `sentry-core/src/utils.rs` | 3-11 | Not a confirmed vulnerability | N/A | N/A |
| 5 | `transmute` of `ThreadId` | `sentry-backtrace/src/integration.rs` | 97 | Not a vulnerability | N/A | N/A |
| 6 | `static mut` in `release_name!` | `sentry-core/src/macros.rs` | 17-35 | Not a vulnerability | N/A | N/A |
