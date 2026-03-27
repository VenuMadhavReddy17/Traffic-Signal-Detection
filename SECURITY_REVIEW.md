# Security Code Review: getsentry/sentry-rust

**Reviewed Repository:** https://github.com/getsentry/sentry-rust
**Review Date:** 2026-03-27
**Reviewer Role:** Senior Product Security Engineer / Bug Bounty Researcher
**Scope:** All Rust source files across all crates in the workspace

---

## Executive Summary

After a thorough source code review of the `sentry-rust` SDK (v0.47.0), covering all 117 Rust source files across 14 crates, I identified **no confirmed remotely exploitable security vulnerabilities**. The codebase is well-structured, uses Rust's safety guarantees effectively, and demonstrates good security hygiene overall. Several crates explicitly `#![deny(unsafe_code)]`.

However, I identified a small number of **code-level findings** that represent real, observable behaviors with security-adjacent implications. These are documented below with full code evidence.

---

## Finding 1: DSN Secret Key Exposed in Debug Logging

- **File:** `sentry-types/src/dsn.rs`, function `fmt::Display for Dsn`, lines 148–161
- **Triggered from:** `sentry/src/init.rs`, line 109

### Code Snippet (Vulnerability Site)

```rust
// sentry-types/src/dsn.rs, lines 148-161
impl fmt::Display for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}://{}:", self.scheme, self.public_key)?;
        if let Some(ref secret_key) = self.secret_key {
            write!(f, "{secret_key}")?;   // <-- SECRET KEY WRITTEN TO OUTPUT
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

```rust
// sentry/src/init.rs, line 109
if let Some(dsn) = client.dsn() {
    sentry_debug!("enabled sentry client for DSN {}", dsn);  // Display trait used here
}
```

```rust
// sentry-core/src/macros.rs, lines 56-65
macro_rules! sentry_debug {
    ($($arg:tt)*) => {
        $crate::Hub::with(|hub| {
            if hub.client().map_or(false, |c| c.options().debug) {
                eprint!("[sentry] ");
                eprintln!($($arg)*);    // <-- Outputs to stderr
            }
        });
    }
}
```

Additionally, the `Dsn` struct derives `Debug` (line 65: `#[derive(Clone, Eq, PartialEq, Hash, Debug)]`) which will also expose all fields including `secret_key` when debug-printed.

### Root Cause

The `Display` implementation for `Dsn` includes the `secret_key` in its output. When `debug: true` is set in `ClientOptions`, the DSN (including the secret key) is printed to `stderr` via `sentry_debug!`. This is also relevant when the DSN is serialized (e.g., in envelope headers, serde serialization via `impl_str_serde!`).

### Exploitation Scenario

1. Application configures Sentry with `debug: true` and a DSN containing a secret key (legacy DSN format).
2. On initialization, `sentry_debug!("enabled sentry client for DSN {}", dsn)` is called.
3. The secret key is written to `stderr` in plaintext.
4. In containerized/cloud environments, `stderr` is often captured in centralized logging systems (CloudWatch, Stackdriver, ELK, etc.).
5. An attacker with access to those log aggregation systems (or log files) obtains the DSN secret key.

### Impact

- **Confidentiality:** Medium — DSN secret key exposure allows an attacker to submit events to the Sentry project, potentially poisoning error data or consuming quota.
- **Note:** Modern Sentry DSNs typically don't include a secret key (public DSNs are the norm). This finding primarily affects users with legacy DSNs.

### CWE

- CWE-532: Insertion of Sensitive Information into Log File

### Final Verdict

**Valid vulnerability (Low severity)** — The secret key is included in log output when debug mode is enabled. While debug mode is opt-in and modern DSNs are typically public-only, this is a real information disclosure pathway visible in the code.

---

## Finding 2: `unsafe` Transmute of `ThreadId` to `u64` — Undefined Behavior

- **File:** `sentry-backtrace/src/integration.rs`, function `current_thread`, line 97

### Code Snippet

```rust
// sentry-backtrace/src/integration.rs, lines 94-98
pub fn current_thread(with_stack: bool) -> Thread {
    // NOTE: `as_u64` is nightly only
    // See https://github.com/rust-lang/rust/issues/67939
    let thread_id: u64 = unsafe { std::mem::transmute(thread::current().id()) };
    Thread {
        id: Some(thread_id.to_string().into()),
```

### Root Cause

`std::thread::ThreadId` is transmuted to `u64`. The internal representation of `ThreadId` is `NonZero<u64>` as of current Rust stdlib, but this is **not** a public API guarantee. The Rust standard library explicitly does not guarantee the internal layout of `ThreadId`. If the Rust stdlib changes `ThreadId`'s internal representation (e.g., to a different size type, or adds fields), this transmute becomes undefined behavior — potentially reading garbage memory, causing crashes, or producing incorrect thread identification.

### Exploitation Scenario

This is not directly exploitable by an external attacker. However:

1. A future Rust compiler/stdlib update changes the internal layout of `ThreadId`.
2. The transmute reads incorrect memory, producing wrong thread IDs.
3. In the worst case (size mismatch), this causes undefined behavior, including potential memory corruption.

### Impact

- **Availability:** Low — could cause crashes or panics on future Rust versions.
- **Integrity:** Low — thread IDs reported in Sentry events may be incorrect.

### CWE

- CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')

### Final Verdict

**Valid code quality / future-safety issue, not currently exploitable.** The transmute works today because `ThreadId` happens to be `NonZero<u64>`, but the reliance on unstable internal layout is unsound. The code already references the nightly-only `as_u64()` tracking issue, indicating awareness.

---

## Finding 3: `static mut` + `unsafe` in `release_name!` Macro — Unsound Pattern

- **File:** `sentry-core/src/macros.rs`, function/macro `release_name!`, lines 18–35

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

This macro uses `static mut` for both `INIT` (a `Once`) and `RELEASE` (an `Option<String>`). `static mut` is deprecated/being phased out and access to it is inherently unsound in the general case. While `Once::call_once` provides thread-safety for the initialization, the subsequent read of `RELEASE` on line 29 is a data race if another thread is concurrently calling `release_name!()` before `call_once` completes, because `static mut` accesses are not synchronized.

Additionally, `transmute(x.as_str())` on line 30 extends the lifetime of a `&str` to `'static`. This is sound here because `RELEASE` is a `static` that is never mutated after `call_once`, but it relies on reasoning about the unsafe code that could break with refactoring.

In practice, `Once::call_once` ensures the write happens exactly once and all subsequent reads see the written value (it provides the necessary memory ordering). So the pattern is **effectively safe in practice** but technically relies on reasoning that Rust's `static mut` rules don't guarantee.

### Impact

- **Availability:** Extremely low — the `Once` synchronization effectively prevents the data race in practice.
- This is an unsound pattern that Rust is moving away from (see `static mut` deprecation RFC).

### CWE

- CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (theoretical)

### Final Verdict

**Not a confirmed vulnerability in practice.** The `Once` synchronization effectively prevents data races. However, this is a known anti-pattern (`static mut`) that should be migrated to `OnceLock` or `LazyLock`. It is not exploitable.

---

## Finding 4: `accept_invalid_certs` Option Disables TLS Verification

- **File:** `sentry-core/src/clientoptions.rs`, line 181; `sentry/src/transports/reqwest.rs`, line 36; `sentry/src/transports/curl.rs`, lines 47-48; `sentry/src/transports/ureq.rs`, line 42; `sentry/src/defaults.rs`, lines 112-114

### Code Snippet

```rust
// sentry/src/transports/reqwest.rs, lines 35-37
if options.accept_invalid_certs {
    builder = builder.danger_accept_invalid_certs(true);
}

// sentry/src/transports/curl.rs, lines 46-49
if accept_invalid_certs {
    handle.ssl_verify_host(false).unwrap();
    handle.ssl_verify_peer(false).unwrap();
}

// sentry/src/transports/ureq.rs, lines 39-44
builder = builder.tls_config(
    TlsConfig::builder()
        .provider(TlsProvider::NativeTls)
        .disable_verification(options.accept_invalid_certs)
        .build(),
);

// sentry/src/defaults.rs, lines 112-114
if let Ok(accept_invalid_certs) = std::env::var("SSL_VERIFY") {
    opts.accept_invalid_certs = !accept_invalid_certs.parse().unwrap_or(true);
}
```

### Root Cause

The `accept_invalid_certs` option is configurable both programmatically and via the `SSL_VERIFY` environment variable (in `defaults.rs`). When enabled, it completely disables TLS certificate verification across all three transport backends (reqwest, curl, ureq).

The documentation already warns about this:
```rust
/// # Warning
///
/// This introduces significant vulnerabilities, and should only be used as a last resort.
pub accept_invalid_certs: bool,
```

The default value is `false`, which is correct.

### Exploitation Scenario

1. An application sets `SSL_VERIFY=false` as an environment variable (e.g., for testing) and forgets to remove it in production.
2. All Sentry event submissions are now sent without TLS certificate verification.
3. An attacker in a MITM position can intercept all Sentry traffic, including error data, user information, breadcrumbs, and the DSN/auth headers.
4. The attacker can also inject fake responses, manipulating rate limiting behavior.

### Impact

- **Confidentiality:** High (in MITM scenario) — all event data can be intercepted.
- **Integrity:** High (in MITM scenario) — event data can be modified in transit.

### CWE

- CWE-295: Improper Certificate Validation

### Final Verdict

**Not a vulnerability in the SDK itself** — this is an intentional, documented opt-in feature with a safe default (`false`). The SDK correctly warns about the danger. However, the environment variable `SSL_VERIFY` provides an indirect attack vector: if an attacker can set environment variables (e.g., via a compromised CI/CD pipeline or container misconfiguration), they can silently disable TLS verification. This is by design but worth noting.

---

## Finding 5: HTTP Scheme Allowed in DSN (No Forced HTTPS)

- **File:** `sentry-types/src/dsn.rs`, function `from_str`, lines 190-194

### Code Snippet

```rust
// sentry-types/src/dsn.rs, lines 190-194
let scheme = match url.scheme() {
    "http" => Scheme::Http,
    "https" => Scheme::Https,
    _ => return Err(ParseDsnError::InvalidScheme),
};
```

### Root Cause

The DSN parser accepts both `http://` and `https://` schemes without warning or enforcement. If a user configures a DSN with `http://`, all Sentry event data (including potentially sensitive error information, user data, breadcrumbs, etc.) is sent unencrypted.

### Impact

- **Confidentiality:** Medium — event data sent over plaintext HTTP can be intercepted.
- **Note:** This is a design choice to support development/self-hosted environments. The SDK does not force or warn about HTTP usage.

### CWE

- CWE-319: Cleartext Transmission of Sensitive Information

### Final Verdict

**Not a vulnerability — intentional design choice.** Sentry SDKs across all languages accept HTTP DSNs for self-hosted and development environments. This is standard behavior.

---

## Areas Reviewed with No Issues Found

### Unsafe Code Review
- **`hub_impl.rs` UnsafeCell usage (lines 55, 72, 174):** Sound — the `UnsafeCell` is in a thread-local, never shared across threads. The `SwitchGuard` is correctly `!Send` (enforced via `PhantomData<MutexGuard>`).
- **`futures.rs` `map_unchecked_mut` (line 37):** Sound — this is the standard structural pinning pattern for futures. The `SentryFuture` struct maintains pinning invariants correctly.
- **`contexts/utils.rs` `sysctlbyname` FFI (lines 12-48):** Sound — proper null-termination, size checking before buffer allocation, and error handling on return codes.

### Network/Transport Security
- All transports properly handle rate limiting responses.
- Auth headers (`X-Sentry-Auth`) are constructed from validated DSN components.
- No header injection vulnerabilities — auth values come from URL-parsed components.
- Proxy configuration properly handled across all transports.

### Input Validation
- DSN parsing validates scheme, requires username (public key), validates project ID, and requires a host.
- Envelope parsing (`from_slice`) properly bounds-checks payload lengths and handles malformed input with proper error types.
- Crontab validation (`crontab_validator.rs`) properly validates all fields with bounded ranges.

### Concurrency
- Hub stack uses `RwLock` with proper poison error handling (`unwrap_or_else(PoisonError::into_inner)`).
- Transport threads use `SyncSender` with bounded channels (size 30), preventing unbounded memory growth.
- `try_send` is used for envelope submission, preventing blocking when the channel is full.
- Session flusher and log batcher properly use `RwLock` for thread-safe access.

### Data Serialization
- All protocol types use `serde` with proper derive macros.
- No custom deserialization that could lead to injection.
- Envelope parsing properly validates item headers and payload lengths.

### PII Handling
- The `sentry-actix` integration properly filters sensitive headers via `is_sensitive_header()`.
- Request URL scrubbing via `scrub_pii_from_url()`.
- `send_default_pii` flag properly gates PII collection.
- Request body capture is gated by both `send_default_pii` and `max_request_body_size`.

---

## Summary Table

| # | Finding | File | Severity | Exploitable | CWE | Verdict |
|---|---------|------|----------|-------------|-----|---------|
| 1 | DSN secret key in debug logs | `dsn.rs:148-161`, `init.rs:109` | Low | Yes (requires debug=true + legacy DSN) | CWE-532 | Valid vulnerability |
| 2 | ThreadId transmute to u64 | `integration.rs:97` | Informational | No (future risk) | CWE-843 | Code quality issue |
| 3 | `static mut` in release_name! | `macros.rs:18-35` | Informational | No | CWE-362 | Not a vulnerability |
| 4 | `accept_invalid_certs` TLS bypass | `clientoptions.rs:181`, transports | N/A | By design (opt-in) | CWE-295 | Not a vulnerability (by design) |
| 5 | HTTP scheme in DSN | `dsn.rs:190-194` | N/A | By design | CWE-319 | Not a vulnerability (by design) |

---

## Conclusion

The `sentry-rust` SDK demonstrates strong security practices overall. Rust's type system and ownership model prevent entire classes of vulnerabilities (buffer overflows, use-after-free, data races). The codebase makes minimal use of `unsafe` code, and several crates explicitly forbid it with `#![deny(unsafe_code)]`.

The only **confirmed vulnerability** is Finding 1 (DSN secret key in debug logs), which is **low severity** because it requires both `debug: true` (opt-in) and a legacy DSN with a secret key. No remotely exploitable, high-severity vulnerabilities were found.
