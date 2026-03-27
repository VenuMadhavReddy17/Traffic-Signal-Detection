# Security Review: DSN Parsing and Credential Handling in sentry-rust

**Date:** 2026-03-27
**Scope:** DSN parsing, credential storage, serialization, logging, and auth header construction
**Repository:** sentry-rust (at /tmp/sentry-rust)

---

## Executive Summary

The review identified **5 real findings** related to credential exposure through `Display`, `Debug`, serialization, and logging, plus **2 design observations** and **3 confirmed non-issues**. The most significant pattern is that the `Dsn` struct's `Display` and derived `Debug` implementations include the secret key, and this propagates through logging, serialization, and debug output of containing types (`Client`, `ClientOptions`).

---

## Finding 1: `Display` for `Dsn` Includes the Secret Key [REAL — LOW SEVERITY]

**File:** `sentry-types/src/dsn.rs`
**Function:** `<Dsn as fmt::Display>::fmt`
**Lines:** 148–161

```
148:161:sentry-types/src/dsn.rs
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

**Analysis:** The `Display` implementation reconstructs the full DSN URL including the secret key in the password position (e.g. `https://publickey:secretkey@host/project`). Any code that calls `.to_string()`, uses `format!("{}", dsn)`, or logs a `Dsn` value will include the secret key in plaintext.

**Reasoning — Low severity, not a bug per se:** This is the standard DSN URL format. The `Display` implementation is designed to produce a round-trippable string representation (`FromStr` <-> `Display`). The secret key is part of the DSN URL spec. However, this becomes a problem when the `Display` output flows into logs, debug output, or error messages where the developer didn't intend to expose the secret. The real risk is in the *consumers* of this `Display` output (see Findings 3, 5, 6, 7).

---

## Finding 2: Derived `Debug` on `Dsn` Exposes the Secret Key [REAL — LOW SEVERITY]

**File:** `sentry-types/src/dsn.rs`
**Lines:** 65–74

```
65:74:sentry-types/src/dsn.rs
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Dsn {
    scheme: Scheme,
    public_key: String,
    secret_key: Option<String>,
    host: String,
    port: Option<u16>,
    path: String,
    project_id: ProjectId,
}
```

**Analysis:** The `Debug` derive will produce output like:
```
Dsn { scheme: Https, public_key: "abc123", secret_key: Some("MY_ACTUAL_SECRET"), host: "sentry.io", ... }
```

This means any `format!("{:?}", dsn)` or debug logging that prints a `Dsn` value will include the secret key in plaintext. A manual `Debug` implementation could redact this field (e.g., `secret_key: Some("[REDACTED]")`).

**Reasoning — Low severity:** `Debug` output is typically only seen by developers during debugging, not by end-users. However, it flows into the `Debug` implementations of `Client` and `ClientOptions` (see Findings 6 and 7), amplifying the exposure surface.

---

## Finding 3: Debug Log in `init()` Leaks DSN with Secret Key [REAL — MEDIUM SEVERITY]

**File:** `sentry/src/init.rs`
**Function:** `init`
**Lines:** 108–109

```
107:112:sentry/src/init.rs
    Hub::with(|hub| hub.bind_client(Some(client.clone())));
    if let Some(dsn) = client.dsn() {
        sentry_debug!("enabled sentry client for DSN {}", dsn);
    } else {
        sentry_debug!("initialized disabled sentry client due to disabled or invalid DSN");
    }
```

**Analysis:** When `ClientOptions::debug` is `true`, this writes the full DSN (including secret key via `Display`) to stderr. The `sentry_debug!` macro (defined in `sentry-core/src/macros.rs:56-65`) writes to stderr using `eprintln!`:

```
56:65:sentry-core/src/macros.rs
macro_rules! sentry_debug {
    ($($arg:tt)*) => {
        $crate::Hub::with(|hub| {
            if hub.client().map_or(false, |c| c.options().debug) {
                eprint!("[sentry] ");
                eprintln!($($arg)*);
            }
        });
    }
}
```

**Reasoning — Medium severity:** This is the highest-impact finding. When a developer enables `debug: true` in their client options (common during development and sometimes left on in staging/production), every client initialization logs the secret key to stderr. In containerized environments, stderr is often aggregated into centralized logging systems (ELK, CloudWatch, Datadog, etc.), where the secret could be visible to a wide audience. The fix would be to redact the secret from the logged DSN, e.g., log only the public-key portion or mask the password.

---

## Finding 4: Serde Serialization of `Dsn` Includes the Secret Key [REAL — LOW SEVERITY]

**File:** `sentry-types/src/dsn.rs`
**Line:** 215 (invocation), `sentry-types/src/macros.rs` lines 8–18 (definition)

```
215:215:sentry-types/src/dsn.rs
impl_str_serde!(Dsn);
```

The `impl_str_serde!` macro generates a `Serialize` impl that calls `self.to_string()`:

```
8:18:sentry-types/src/macros.rs
macro_rules! impl_str_ser {
    ($type:ty) => {
        impl ::serde::ser::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::ser::Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }
    };
}
```

**Analysis:** Since `to_string()` calls `Display::fmt` which includes the secret key, any JSON (or other serde) serialization of a `Dsn` value will contain the secret key. This matters if `Dsn` values are serialized to logs, config files, API responses, or telemetry payloads.

**Reasoning — Low severity:** The DSN is a URL, and its serialized form is expected to be the full URL. However, consumers should be aware that serializing a `Dsn` value is equivalent to serializing the secret key.

---

## Finding 5: `Debug` for `Client` and `ClientOptions` Propagates Secret Key Exposure [REAL — LOW SEVERITY]

**File:** `sentry-core/src/client.rs`, lines 68–75
**File:** `sentry-core/src/clientoptions.rs`, lines 221–283

```
68:75:sentry-core/src/client.rs
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("dsn", &self.dsn())
            .field("options", &self.options)
            .finish()
    }
}
```

```
240:242:sentry-core/src/clientoptions.rs
        let mut debug_struct = f.debug_struct("ClientOptions");
        debug_struct
            .field("dsn", &self.dsn)
```

**Analysis:** Both `Client::Debug` and `ClientOptions::Debug` include the `Dsn` value, which uses the derived `Debug` that exposes the secret key. Any debug-formatting of a `Client` or `ClientOptions` (e.g., in assertions, logging frameworks, error reports) will include the secret key.

**Reasoning — Low severity:** Debug formatting of these types is less common in production than the `sentry_debug!` logging in Finding 3, but it widens the surface area for accidental exposure.

---

## Finding 6: Curl Transport Logs Outgoing HTTP Headers Including Auth Secret [REAL — LOW SEVERITY]

**File:** `sentry/src/transports/curl.rs`
**Lines:** 80–91

```
80:91:sentry/src/transports/curl.rs
            handle.verbose(true).unwrap();
            handle
                .debug_function(move |info, data| {
                    let prefix = match info {
                        curl::easy::InfoType::HeaderIn => "< ",
                        curl::easy::InfoType::HeaderOut => "> ",
                        curl::easy::InfoType::DataOut => "",
                        _ => return,
                    };
                    sentry_debug!("curl: {}{}", prefix, String::from_utf8_lossy(data).trim());
                })
                .unwrap();
```

**Analysis:** The curl transport always sets `verbose(true)` and logs outgoing headers (`HeaderOut`) via `sentry_debug!`. The outgoing headers include `X-Sentry-Auth` which contains `sentry_secret=<actual_secret>` when a secret key is configured. When `debug: true` is set on the client, these headers are printed to stderr. This is a secondary exposure path for the secret key through HTTP header logging.

**Reasoning — Low severity:** This only triggers when `debug: true` is set, and the same secret is already exposed by Finding 3. However, this also logs the auth header on *every request*, not just at init time, increasing the volume of secret exposure.

---

## Design Observation 1: `Auth::Display` and `Auth::Serialize` Include the Secret [BY DESIGN]

**File:** `sentry-types/src/auth.rs`
**Lines:** 130–148 (Display), 29–41 (Serialize derive)

```
130:148:sentry-types/src/auth.rs
impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Sentry sentry_key={}, sentry_version={}",
            self.key, self.version
        )?;
        if let Some(ts) = self.timestamp {
            write!(f, ", sentry_timestamp={}", datetime_to_timestamp(&ts))?;
        }
        if let Some(ref client) = self.client {
            write!(f, ", sentry_client={client}")?;
        }
        if let Some(ref secret) = self.secret {
            write!(f, ", sentry_secret={secret}")?;
        }
        Ok(())
    }
}
```

**Analysis:** The `Auth::Display` output includes `sentry_secret=<value>` when a secret key is present. This is used in all transport implementations to construct the `X-Sentry-Auth` HTTP header:

- `reqwest.rs:64` — `let auth = dsn.to_auth(Some(&user_agent)).to_string();`
- `curl.rs:35` — `let auth = dsn.to_auth(Some(&user_agent)).to_string();`
- `ureq.rs:83` — `let auth = dsn.to_auth(Some(&user_agent)).to_string();`
- `embedded_svc_http.rs:31` — `let auth = dsn.to_auth(Some(user_agent)).to_string();`

**Reasoning — By design:** The `X-Sentry-Auth` header is the Sentry authentication mechanism. Including the secret in the auth header is the intended behavior when a secret key exists. The `Auth::Display` format matches the Sentry auth header specification. This is not a vulnerability.

---

## Design Observation 2: `Auth` Struct Has `#[derive(Debug, Serialize)]` [ACCEPTABLE]

**File:** `sentry-types/src/auth.rs`, line 29

```
29:41:sentry-types/src/auth.rs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Auth {
    #[serde(skip)]
    timestamp: Option<SystemTime>,
    #[serde(rename = "sentry_client")]
    client: Option<String>,
    #[serde(rename = "sentry_version")]
    version: u16,
    #[serde(rename = "sentry_key")]
    key: String,
    #[serde(rename = "sentry_secret")]
    secret: Option<String>,
}
```

**Reasoning:** The `Auth` struct's `Debug` and `Serialize` implementations both expose the secret field. This is acceptable because `Auth` is explicitly an authentication token object — its purpose is to carry credentials for transmission. Users working with `Auth` objects should expect them to contain secrets.

---

## Confirmed Non-Issues

### Non-Issue 1: `ParseDsnError` Does Not Leak Credentials

**File:** `sentry-types/src/dsn.rs`, lines 10–28

The error variants are all static strings: "no valid url provided", "no valid scheme", "username is empty", "empty path", "invalid project id". The failed DSN input string is never included in the error message. This is correct behavior.

### Non-Issue 2: API URLs Do Not Include Credentials

**File:** `sentry-types/src/dsn.rs`, lines 85–110

The `api_url()`, `store_api_url()`, and `envelope_api_url()` methods construct URLs using only `scheme`, `host`, `port`, `path`, and `project_id`. Credentials are never included in these URLs. Instead, credentials are passed via the `X-Sentry-Auth` header (the proper approach).

### Non-Issue 3: DSC (Dynamic Sampling Context) Only Uses the Public Key

**File:** `sentry-core/src/performance.rs`, lines 879–881

```
879:881:sentry-core/src/performance.rs
                    if let Some(public_key) = client.dsn().map(|dsn| dsn.public_key()) {
                        dsc = dsc.with_public_key(public_key.to_owned());
                    }
```

Only the public key is extracted for the dynamic sampling context. The secret key is never included in trace propagation headers or baggage. This is correct.

---

## Recommendations

1. **Implement a manual `Debug` for `Dsn`** that redacts `secret_key`:
   ```rust
   impl fmt::Debug for Dsn {
       fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
           f.debug_struct("Dsn")
               .field("scheme", &self.scheme)
               .field("public_key", &self.public_key)
               .field("secret_key", &self.secret_key.as_ref().map(|_| "[REDACTED]"))
               .field("host", &self.host)
               .field("port", &self.port)
               .field("path", &self.path)
               .field("project_id", &self.project_id)
               .finish()
       }
   }
   ```

2. **Redact the secret key in the `sentry_debug!` log in `init()`**: Instead of logging `{}` (Display, which includes the secret), log a redacted version. For example:
   ```rust
   sentry_debug!("enabled sentry client for DSN {}://{}@{}", dsn.scheme(), dsn.public_key(), dsn.host());
   ```

3. **Consider a `Dsn::to_redacted_string()` method** for safe logging:
   ```rust
   pub fn to_redacted_string(&self) -> String {
       format!("{}://{}:[REDACTED]@{}...", self.scheme, self.public_key, self.host)
   }
   ```

4. **Consider filtering `sentry_secret` from curl verbose logging** in `curl.rs` when logging `HeaderOut` data, or at minimum avoid logging headers when verbose mode is set.

5. **Note on secret key deprecation**: Sentry has deprecated the use of secret keys in DSNs. Modern DSNs typically only have a public key. However, older DSNs may still carry a secret key, and the code correctly supports both forms. The recommendations above are defense-in-depth measures.
