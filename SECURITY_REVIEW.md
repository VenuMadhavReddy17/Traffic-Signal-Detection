# Security Code Review: getsentry/sentry-rust

**Repository:** https://github.com/getsentry/sentry-rust
**Review Date:** 2026-03-27
**Reviewer Role:** Senior Product Security Engineer / Bug Bounty Researcher
**Scope:** Full source code review of all crates in the sentry-rust workspace

---

## Executive Summary

After a thorough source code review of the `getsentry/sentry-rust` repository, I identified **several findings** ranging from confirmed code-level concerns to items that are **not exploitable vulnerabilities** in the context of this SDK. The sentry-rust SDK is a *client-side library* that runs within the application process—it is not a server. Most of the code processes data generated internally by the application (not attacker-controlled input from the network). This significantly limits the attack surface.

The codebase shows overall good security hygiene: many crates use `#![deny(unsafe_code)]`, DSN parsing delegates to the well-tested `url` crate, and PII-scrubbing utilities are in place for HTTP integrations. Below are the detailed findings.

---

## Finding 1: DSN Secret Key Logged in Plaintext via `sentry_debug!`

**File:** `sentry/src/init.rs`, function `init`, line 109
**Also:** `sentry-types/src/dsn.rs`, `impl Display for Dsn`, lines 148-161

### Code Snippet (init.rs)

```rust
// sentry/src/init.rs, line 109
if let Some(dsn) = client.dsn() {
    sentry_debug!("enabled sentry client for DSN {}", dsn);
}
```

### Code Snippet (dsn.rs - Display impl)

```rust
// sentry-types/src/dsn.rs, lines 148-161
impl fmt::Display for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}://{}:", self.scheme, self.public_key)?;
        if let Some(ref secret_key) = self.secret_key {
            write!(f, "{secret_key}")?;
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

### Root Cause

The `Display` implementation for `Dsn` includes the `secret_key` in its output. When `sentry_debug!` is invoked with `debug: true` in `ClientOptions`, the full DSN—including the secret key—is printed to stderr. The `Debug` derive on `Dsn` (line 65) also outputs all fields including `secret_key`.

### Exploitation Scenario

1. Developer enables `debug: true` in `ClientOptions` (or a debug build has it enabled).
2. Application logs are captured by a logging aggregator, shipped to a log management service, or visible in container stdout/stderr.
3. An attacker with read access to logs (e.g., a compromised monitoring system, overly permissive log access) can extract the DSN secret key.
4. While Sentry's modern auth primarily uses the public key, the secret key (when present) provides stronger authentication to older Sentry API endpoints.

### Impact

- **Confidentiality:** Medium — DSN secret key leaked in logs
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

### Verdict: **Low-severity information disclosure concern, but not a high-impact exploitable vulnerability.**

In modern Sentry deployments, the secret key in DSNs is deprecated and the public key alone suffices. The `debug` flag must be explicitly enabled. However, the `Display` impl unconditionally including the secret is a design choice that could be improved by redacting or omitting it.

---

## Finding 2: `SSL_VERIFY` Environment Variable Can Disable TLS Certificate Verification

**File:** `sentry/src/defaults.rs`, function `apply_defaults`, lines 112-114

### Code Snippet

```rust
// sentry/src/defaults.rs, lines 112-114
if let Ok(accept_invalid_certs) = std::env::var("SSL_VERIFY") {
    opts.accept_invalid_certs = !accept_invalid_certs.parse().unwrap_or(true);
}
```

### How it Propagates — reqwest transport (sentry/src/transports/reqwest.rs, lines 35-36)

```rust
if options.accept_invalid_certs {
    builder = builder.danger_accept_invalid_certs(true);
}
```

### How it Propagates — ureq transport (sentry/src/transports/ureq.rs, lines 42-43)

```rust
.disable_verification(options.accept_invalid_certs)
```

### How it Propagates — curl transport (sentry/src/transports/curl.rs, lines 47-48)

```rust
handle.ssl_verify_host(false).unwrap();
handle.ssl_verify_peer(false).unwrap();
```

### Root Cause

Setting `SSL_VERIFY=false` (or `SSL_VERIFY=0`) causes `accept_invalid_certs` to be set to `true`, which disables all TLS certificate verification across all transport backends (reqwest, ureq, curl). This means a Man-in-the-Middle (MITM) attacker could intercept Sentry event submissions.

### Exploitation Scenario

1. An attacker who can control environment variables (e.g., via a container orchestration misconfiguration, CI/CD pipeline injection, or shared hosting) sets `SSL_VERIFY=false`.
2. All TLS certificate verification for Sentry traffic is disabled.
3. A network-positioned attacker performs MITM on Sentry traffic, intercepting events that may contain stack traces, user data, request bodies, and other sensitive application telemetry.

### Impact

- **Confidentiality:** High — all Sentry telemetry can be intercepted
- **Integrity:** Medium — events could be tampered with or dropped
- **CWE:** CWE-295 (Improper Certificate Validation)

### Verdict: **Valid concern, but requires environmental control by attacker.**

This is a *documented configuration option* (`accept_invalid_certs`) that can also be set via the environment. The risk is real only if an attacker can modify the process environment. The defaults are secure (`accept_invalid_certs: false`).

---

## Finding 3: `std::mem::transmute` of `ThreadId` to `u64`

**File:** `sentry-backtrace/src/integration.rs`, function `current_thread`, line 97

### Code Snippet

```rust
// sentry-backtrace/src/integration.rs, line 97
let thread_id: u64 = unsafe { std::mem::transmute(thread::current().id()) };
```

### Root Cause

`std::thread::ThreadId` is an opaque type whose internal representation is not guaranteed by the Rust standard library. This `transmute` assumes it has the same size and layout as `u64`. While this has been true in all known rustc versions (the type internally wraps a `NonZeroU64`), the Rust standard library explicitly does not guarantee this layout, meaning a future rustc update could change the internal representation and cause undefined behavior.

### Exploitation Scenario

This is **not directly exploitable by an attacker**. It is a soundness issue that could cause undefined behavior if the Rust standard library's internal representation of `ThreadId` changes. The comment in the code acknowledges this is a workaround for `as_u64()` being nightly-only.

### Impact

- **Availability:** Low risk of undefined behavior on future Rust versions
- **CWE:** CWE-704 (Incorrect Type Conversion or Cast)

### Verdict: **Not a security vulnerability. It is a soundness concern that could cause UB on hypothetical future Rust versions.**

---

## Finding 4: `release_name!` Macro Uses `transmute` to Extend Lifetime

**File:** `sentry-core/src/macros.rs`, function `release_name!` macro, lines 18-35

### Code Snippet

```rust
// sentry-core/src/macros.rs, lines 18-35
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

### Root Cause

The macro uses `static mut` variables (which are inherently unsafe in Rust 2024 edition) and transmutes a `&str` borrow from a `static mut Option<String>` into a `&'static str`. The safety argument is that:
1. `INIT` (`Once`) guarantees the `String` is only written once.
2. The `String` lives in a `static` and is never dropped or moved.

This is technically sound given those invariants, but the use of `static mut` makes it fragile. It is also flagged as a pattern that the Rust ecosystem discourages (newer Rust editions lint against `static mut`).

### Exploitation Scenario

**Not exploitable by an attacker.** The values come from compile-time environment variables (`CARGO_PKG_NAME`, `CARGO_PKG_VERSION`), not from any user/attacker input. The `Once` guard prevents data races.

### Impact

- **None for security.** This is a code quality/soundness concern.
- **CWE:** N/A

### Verdict: **Not a vulnerability.**

---

## Finding 5: `UnsafeCell` Usage in Thread-Local Hub Management

**File:** `sentry-core/src/hub_impl.rs`, lines 17, 55, 72, 174

### Code Snippet

```rust
// sentry-core/src/hub_impl.rs, line 17
thread_local! {
    static THREAD_HUB: (UnsafeCell<Arc<Hub>>, Cell<bool>) = (
        UnsafeCell::new(Arc::new(Hub::new_from_top(&PROCESS_HUB.0))),
        Cell::new(PROCESS_HUB.1 == thread::current().id())
    );
}

// line 55 (inside SwitchGuard::new)
let thread_hub = unsafe { &mut *thread_hub.get() };

// line 174 (inside Hub::with)
f(unsafe { &*hub.get() })
```

### Root Cause

`UnsafeCell` is used for the thread-local hub to allow mutable access without `RefCell` overhead. Since it's a `thread_local!`, the data is inherently single-threaded and not shared between threads. The `SwitchGuard` type is marked `!Send` (via `PhantomData<MutexGuard<'static, ()>>`), preventing it from being sent to another thread.

### Exploitation Scenario

**Not exploitable.** Thread-local storage is by definition not shared across threads, so the `unsafe` dereferences are sound. The `!Send` bound on `SwitchGuard` prevents misuse.

### Impact

- **None.** Sound usage of `UnsafeCell` within `thread_local!`.
- **CWE:** N/A

### Verdict: **Not a vulnerability.**

---

## Finding 6: Pin Projection in `SentryFuture`

**File:** `sentry-core/src/futures.rs`, function `poll`, line 37

### Code Snippet

```rust
// sentry-core/src/futures.rs, line 37
let future = unsafe { self.map_unchecked_mut(|s| &mut s.future) };
```

### Root Cause

This performs structural pin projection to get a pinned mutable reference to the inner `future` field. The safety invariant requires that:
1. The `future` field is structurally pinned (i.e., `SentryFuture` doesn't implement `Unpin` unconditionally, doesn't move `future` out of `self`, and doesn't expose `&mut future`).

Reviewing the struct, `SentryFuture` only has `hub: Arc<Hub>` (which is `Unpin`) and `future: F`. The struct doesn't implement `Drop` in a way that moves `future`, and doesn't provide any API to move `future` out. This projection is sound.

### Verdict: **Not a vulnerability.** Sound pin projection.

---

## Finding 7: `sysctlbyname` FFI Call on macOS

**File:** `sentry-contexts/src/utils.rs`, function `sysctlbyname_call`, lines 11-48

### Code Snippet

```rust
// sentry-contexts/src/utils.rs, lines 12-48
fn sysctlbyname_call(name: &str) -> Option<String> {
    unsafe {
        let c_name = match CString::new(name) {
            Ok(name) => name.into_bytes_with_nul(),
            Err(_e) => return None,
        };
        let mut size = 0;
        let res = libc::sysctlbyname(
            c_name.as_ptr() as _,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        );
        if res != 0 { return None; }

        let mut buf = vec![0u8; size];
        let res = libc::sysctlbyname(
            c_name.as_ptr() as _,
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            ptr::null_mut(),
            0,
        );
        if res != 0 { return None; }
        // ...
    }
}
```

### Root Cause

This FFI code is only called with hardcoded kernel parameter names (`"hw.model"`, `"kern.osproductversion"`, `"kern.osversion"`), not with any user-supplied input. There is a potential TOCTOU (time-of-check, time-of-use) issue between the two `sysctlbyname` calls: the size could change between calls. However, `sysctlbyname` for these particular system parameters returns fixed-size data, and if the buffer is too small, the second call simply fails (returns non-zero), which is handled.

### Verdict: **Not a vulnerability.** Hardcoded inputs, proper error handling.

---

## Finding 8: Request Body Capture Without Content-Length Validation Edge Case

**File:** `sentry-actix/src/lib.rs`, function `should_capture_request_body`, lines 214-243

### Code Snippet

```rust
// sentry-actix/src/lib.rs, lines 236-243
let is_within_size_limit = headers
    .get(header::CONTENT_LENGTH)
    .and_then(|h| h.to_str().ok())
    .and_then(|content_length| content_length.parse::<usize>().ok())
    .map(|content_length| max_request_body_size.is_within_size_limit(content_length))
    .unwrap_or(false);

!is_chunked && is_valid_content_type && is_within_size_limit
```

### Root Cause

The body capture decision is based on the `Content-Length` header, which is client-controlled. An attacker could send a request with a small `Content-Length` header but a much larger actual body (HTTP request smuggling style). However, actix-web's own body parsing would enforce the declared content length, and the `is_within_size_limit` check defaults to `false` when Content-Length is missing. This is a defense-in-depth concern rather than an exploitable vulnerability.

### Verdict: **Not a vulnerability.** The actix-web framework handles body size enforcement.

---

## Finding 9: Sensitive Header List May Be Incomplete

**File:** `sentry-core/src/utils.rs`, lines 3-11

### Code Snippet

```rust
// sentry-core/src/utils.rs, lines 3-11
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

### Root Cause

The sensitive header list is a static allowlist. Headers like `X-Auth-Token`, `X-CSRF-Token`, `Bearer`, or custom authentication headers used by specific applications are not included. When `send_default_pii` is `false` (the default), these custom auth headers would be captured and sent to Sentry.

### Impact

- **Confidentiality:** Low — application-specific auth tokens in custom headers could be sent to Sentry
- **CWE:** CWE-200 (Exposure of Sensitive Information)

### Verdict: **Not a vulnerability in this code specifically** — this is an inherent limitation of any static allowlist approach. The SDK correctly documents that `with_pii: false` filters *known* sensitive headers, and provides `send_default_pii` and `before_send` callbacks for applications to implement custom scrubbing.

---

## Non-Finding: Random Number Generation for Sampling

**File:** `sentry-core/src/client.rs`, function `sample_should_send`, lines 454-461

```rust
pub fn sample_should_send(&self, rate: f32) -> bool {
    if rate >= 1.0 { true }
    else if rate <= 0.0 { false }
    else { random::<f32>() < rate }
}
```

The `rand::random()` function is used for sampling decisions. This is not a cryptographic context—it's a probabilistic rate limiter—so the use of a non-CSPRNG is appropriate and not a vulnerability.

---

## Non-Finding: HTTP Scheme (non-TLS) Allowed in DSN

**File:** `sentry-types/src/dsn.rs`, lines 190-193

The DSN parser accepts `http://` scheme. This is intentional for development/testing environments and self-hosted Sentry instances on internal networks. It is not a vulnerability in the SDK.

---

## Summary

| # | Finding | Severity | Exploitable? | Verdict |
|---|---------|----------|-------------|---------|
| 1 | DSN secret key logged via `sentry_debug!` | Low | Requires `debug: true` + log access | Information disclosure concern |
| 2 | `SSL_VERIFY` env var disables TLS verification | Medium | Requires env var control | Valid concern, secure by default |
| 3 | `transmute` of `ThreadId` to `u64` | Informational | Not exploitable | Soundness concern, not a vulnerability |
| 4 | `release_name!` macro uses `static mut` + transmute | Informational | Not exploitable | Code quality concern, not a vulnerability |
| 5 | `UnsafeCell` in thread-local Hub | Informational | Not exploitable | Sound usage, not a vulnerability |
| 6 | Pin projection in `SentryFuture` | Informational | Not exploitable | Sound usage, not a vulnerability |
| 7 | `sysctlbyname` FFI on macOS | Informational | Not exploitable | Hardcoded inputs, not a vulnerability |
| 8 | Request body capture Content-Length check | Informational | Not exploitable | Framework enforces limits |
| 9 | Incomplete sensitive header list | Low | Not directly exploitable | Inherent limitation of static allowlist |

**No confirmed high-severity, directly exploitable security vulnerabilities were found after thorough code review.**

The codebase demonstrates good security practices overall:
- Multiple crates use `#![deny(unsafe_code)]`
- DSN parsing delegates to the well-audited `url` crate
- PII scrubbing is implemented for URLs and headers
- TLS verification is enabled by default
- Sensitive header filtering is applied by default in HTTP integrations
- `unsafe` usage is limited and generally well-justified with safety comments
- The `SwitchGuard` is properly marked `!Send` to prevent cross-thread misuse
