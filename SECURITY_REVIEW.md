# Security Review: sentry-rust Serialization, Deserialization, and Input Parsing

**Repository:** /tmp/sentry-rust  
**Date:** 2026-03-27  
**Scope:** Serialization/deserialization, envelope parsing, custom parsers, input validation, integer overflow, buffer allocation, panic paths, session handling, stack trace parsing, and untrusted network data processing.

---

## Executive Summary

The sentry-rust SDK is primarily a **client-side library** that serializes local application data and sends it to a Sentry server. It is **not** a server that receives untrusted data from the network in normal usage. However, the `Envelope::from_slice()` parsing path and DSN/Auth parsing paths do process potentially untrusted data. The codebase is generally well-structured with Rust's safety guarantees providing a strong baseline, but several findings merit attention.

**Critical/High findings: 0**  
**Medium findings: 3**  
**Low findings: 5**  
**Informational: 4**

---

## Finding 1: Envelope Parsing — Integer Addition Overflow in Payload End Calculation (Medium)

**File:** `sentry-types/src/protocol/envelope.rs`  
**Function:** `Envelope::parse_item()`  
**Lines:** 634-636

```rust
let payload_end = match header.length {
    Some(len) => {
        let payload_end = payload_start + len;
        if slice.len() < payload_end {
            return Err(EnvelopeError::UnexpectedEof);
        }
```

**Analysis:**  
The `length` field in `EnvelopeItemHeader` is `Option<usize>`. When a user-controlled `length` value is deserialized from JSON, it arrives as a `usize`. The computation `payload_start + len` can overflow on 32-bit platforms if `payload_start` is small and `len` is close to `usize::MAX`. On overflow, `payload_end` wraps around to a small number, the length check `slice.len() < payload_end` passes, and the subsequent slice operation `slice.get(payload_start..payload_end)` would return `None` (since `payload_end < payload_start` after wrapping) causing an `unwrap()` panic on line 654.

On 64-bit platforms, `serde_json` will parse a JSON number into a `usize` (max ~18.4 exabytes), so while the arithmetic could theoretically overflow, the initial JSON deserialization would need to produce such a value. In practice, serde_json limits integers to i64/u64 range, and `usize` on 64-bit is u64, so overflow is not possible on 64-bit. **On 32-bit platforms, this is exploitable** — a `length` field of `4294967295` (u32::MAX) would overflow when added to any non-zero `payload_start`.

**Exploitability:** Medium on 32-bit targets; Not exploitable on 64-bit targets. Could cause a panic (DoS).

**Recommendation:** Use `payload_start.checked_add(len).ok_or(EnvelopeError::UnexpectedEof)?` instead of bare addition.

---

## Finding 2: Attachment Serialization — Header Injection via Filename (Medium)

**File:** `sentry-types/src/protocol/attachment.rs`  
**Function:** `Attachment::to_writer()`  
**Lines:** 61-79

```rust
pub fn to_writer<W>(&self, writer: &mut W) -> std::io::Result<()>
where
    W: std::io::Write,
{
    writeln!(
        writer,
        r#"{{"type":"attachment","length":{length},"filename":"{filename}","attachment_type":"{at}","content_type":"{ct}"}}"#,
        filename = self.filename,
        length = self.buffer.len(),
        at = self
            .ty
            .as_ref()
            .unwrap_or(&AttachmentType::default())
            .as_str(),
        ct = self
            .content_type
            .as_ref()
            .unwrap_or(&"application/octet-stream".to_string())
    )?;

    writer.write_all(&self.buffer)?;
    Ok(())
}
```

**Analysis:**  
The `filename`, attachment type (`at`), and `content_type` (`ct`) are interpolated directly into a JSON string using Rust's `format!`/`writeln!` macro, **without any JSON escaping**. If a filename contains characters like `"` (double quote) or `\` (backslash), the generated JSON will be malformed or could inject additional JSON fields.

For example, a filename like `foo","evil":"injected` would produce:
```json
{"type":"attachment","length":12,"filename":"foo","evil":"injected","attachment_type":"event.attachment","content_type":"application/octet-stream"}
```

This breaks the envelope format and could cause parsing issues on the receiving server (Sentry Relay). Similar injection is possible via `content_type` and custom `AttachmentType::Custom(String)`.

**Exploitability:** Medium. In normal SDK usage, filenames come from the application developer, not untrusted input. However, if an application passes user-controlled filenames to attachments without sanitization, this could produce malformed envelopes. The impact is limited to malformed data reaching the Sentry server (which likely rejects it), not RCE.

**Recommendation:** Use `serde_json::to_writer` to serialize the attachment header, or at minimum escape the string values with proper JSON escaping before interpolation.

---

## Finding 3: Envelope Item Container Serialization — Unescaped Type in writeln! (Medium)

**File:** `sentry-types/src/protocol/envelope.rs`  
**Function:** `Envelope::to_writer()`  
**Lines:** 524-539

```rust
if let EnvelopeItem::ItemContainer(container) = item {
    writeln!(
        writer,
        r#"{{"type":"{}","item_count":{},"content_type":"{}"}}"#,
        item_type,
        container.len(),
        container.content_type()
    )?;
} else {
    writeln!(
        writer,
        r#"{{"type":"{}","length":{}}}"#,
        item_type,
        item_buf.len()
    )?;
}
```

**Analysis:**  
The `item_type` and `content_type()` values are interpolated into JSON without escaping. Currently, all `item_type` values are hardcoded string literals (`"event"`, `"session"`, etc.) and `content_type()` returns a static string, so this is not exploitable with the current code. However, this pattern is fragile — if a future code change introduces a dynamic or user-influenced type string, it becomes exploitable.

**Exploitability:** Not currently exploitable, but the pattern is a latent vulnerability.

**Recommendation:** Same as Finding 2 — use proper JSON serialization for headers.

---

## Finding 4: `unwrap()` on Slice in Envelope Parsing (Low)

**File:** `sentry-types/src/protocol/envelope.rs`  
**Function:** `Envelope::parse_item()`  
**Line:** 654

```rust
let payload = slice.get(payload_start..payload_end).unwrap();
```

**Analysis:**  
This `unwrap()` can only panic if `payload_start > payload_end`, which in normal execution is prevented by the logic above. However, if Finding 1 (integer overflow) triggers on 32-bit, `payload_end` could wrap to a value less than `payload_start`, making `.get()` return `None` and triggering a panic.

**Exploitability:** Low (only reachable through Finding 1 on 32-bit).

**Recommendation:** Replace with `.ok_or(EnvelopeError::UnexpectedEof)?`.

---

## Finding 5: Stack Trace Parser — `unwrap()` on Integer Parse (Low)

**File:** `sentry-backtrace/src/parse.rs`  
**Function:** `parse_stacktrace()`  
**Lines:** 70-72

```rust
lineno: captures
    .name("lineno")
    .map(|x| x.as_str().parse::<u64>().unwrap()),
colno: captures
    .name("colno")
    .map(|x| x.as_str().parse::<u64>().unwrap()),
```

**Analysis:**  
The regex captures `lineno` and `colno` with the pattern `(?P<lineno>\d+)` and `(?P<colno>\d+)`, which only match digit characters. However, a very long sequence of digits (e.g., more than 20 digits) would cause `parse::<u64>()` to fail with an overflow error, triggering a panic via `unwrap()`.

The `parse_stacktrace` function processes backtrace strings that are generated locally by the Rust runtime/backtrace crate, so in normal operation the input is trusted. If this function were ever used to parse externally-supplied stacktraces, the panic becomes reachable.

**Exploitability:** Low. Input is locally generated. Would require specifically crafted backtrace text with >20-digit line numbers.

**Recommendation:** Replace `unwrap()` with `ok()` or `.unwrap_or(0)`.

---

## Finding 6: Auth Header Parsing — Unlimited Key-Value Pairs (Low)

**File:** `sentry-types/src/auth.rs`  
**Function:** `Auth::from_str()`  
**Lines:** 153-173

```rust
fn from_str(s: &str) -> Result<Auth, ParseAuthError> {
    let mut base_iter = s.splitn(2, ' ');
    let prefix = base_iter.next().unwrap_or("");
    let items = base_iter.next().unwrap_or("");

    if !prefix.eq_ignore_ascii_case("sentry") {
        return Err(ParseAuthError::NonSentryAuth);
    }

    let auth = Self::from_pairs(items.split(',').filter_map(|item| {
        let mut kviter = item.split('=');
        Some((kviter.next()?.trim(), kviter.next()?.trim()))
    }))?;
```

**Analysis:**  
The auth header parser splits on `,` without any limit on the number of key-value pairs. An extremely long auth header string with millions of commas could cause excessive memory allocation and CPU usage during splitting and iteration. However, this is a client-side parser typically used to parse Sentry auth headers which the SDK itself constructs, not arbitrary input.

**Exploitability:** Low. Requires attacker control of the auth header string passed to `Auth::from_str()`, which is uncommon.

---

## Finding 7: Rate Limiter — Float-to-Integer Conversion (Low)

**File:** `sentry/src/transports/ratelimit.rs`  
**Function:** `RateLimiter::update_from_retry_after()`  
**Lines:** 27-28

```rust
pub fn update_from_retry_after(&mut self, header: &str) {
    let new_time = if let Ok(value) = header.parse::<f64>() {
        SystemTime::now() + Duration::from_secs(value.ceil() as u64)
```

**Analysis:**  
A malicious server could return a `Retry-After` header with a very large or negative float value. `value.ceil() as u64` on a negative float produces `0` (Rust saturating cast), and on `f64::MAX` produces `u64::MAX`. `Duration::from_secs(u64::MAX)` combined with `SystemTime::now() +` will panic due to overflow in the `Add` implementation for `SystemTime`.

Similarly in `update_from_sentry_header()` (line 49):
```rust
let new_time = Some(SystemTime::now() + Duration::from_secs(seconds.ceil() as u64));
```

**Exploitability:** Low. Requires a malicious Sentry server returning crafted rate-limit headers. The client would panic (DoS), but this requires MITM or a compromised Sentry server.

**Recommendation:** Use `checked_add` on `SystemTime` and cap the duration to a reasonable maximum (e.g., 24 hours).

---

## Finding 8: DSN `api_url` — Infallible `Url::parse` Assumption (Low)

**File:** `sentry-types/src/dsn.rs`  
**Function:** `Dsn::api_url()`  
**Line:** 99

```rust
fn api_url(&self, endpoint: &str) -> Url {
    use std::fmt::Write;
    let mut buf = format!("{}://{}", self.scheme(), self.host());
    if self.port() != self.scheme.default_port() {
        write!(&mut buf, ":{}", self.port()).unwrap();
    }
    write!(
        &mut buf,
        "{}api/{}/{}/",
        self.path,
        self.project_id(),
        endpoint
    )
    .unwrap();
    Url::parse(&buf).unwrap()
}
```

**Analysis:**  
The `Url::parse(&buf).unwrap()` assumes the constructed URL is always valid. Since the DSN is parsed from a `Url` during construction, the host/scheme/path are already validated. However, `project_id` is stored as an opaque `String` that only checks for non-emptiness. A ProjectId containing URL-special characters like `#` or `?` could potentially cause `Url::parse` to succeed but produce an unexpected URL structure, or in edge cases cause the unwrap to panic.

**Exploitability:** Low. The DSN is typically provided by the application developer or from a known environment variable.

---

## Informational Findings

### Info 1: No Size Limits on Deserialized Collections

Throughout the protocol types (`v7.rs`), collections like `Vec<Frame>`, `Vec<Span>`, `Vec<Breadcrumb>`, `Values<Exception>`, `Map<String, Value>`, etc. are deserialized without any size limits. If `Envelope::from_slice()` processes attacker-controlled data, an adversary could supply JSON with millions of entries in these arrays, causing excessive memory allocation.

However, since this is a client-side SDK and `from_slice()` is not exposed to untrusted network input in normal usage, this is informational.

### Info 2: Unbounded String Fields in Protocol Types

All `String` fields in protocol types (`Event`, `Transaction`, `Session`, etc.) have no maximum length enforcement. Extremely long strings in fields like `message`, `transaction`, `release`, `filename`, etc. could cause memory exhaustion if processed from untrusted input.

### Info 3: `ThreadId::from(i64)` Truncation

In `v7.rs` (line 328-331):
```rust
impl From<i64> for ThreadId {
    fn from(id: i64) -> ThreadId {
        ThreadId::Int(id as u64)
    }
}
```
A negative i64 will be reinterpreted as a large u64 value. This is a semantic issue, not a security vulnerability, but could cause unexpected behavior if negative thread IDs are received.

### Info 4: `Addr::from(i32)` Sign Extension

In `v7.rs` (lines 379-383):
```rust
impl From<i32> for Addr {
    fn from(addr: i32) -> Addr {
        Addr(addr as u64)
    }
}
```
A negative i32 will be sign-extended to a large u64 address value. Same class as Info 3.

---

## Areas Reviewed with No Findings

### Serde Derive Implementations
The vast majority of protocol types use `#[derive(Serialize, Deserialize)]` with standard serde attributes. These are safe by default — serde handles JSON parsing robustly, including proper string escaping on serialization and type validation on deserialization.

### DSN Parsing (`dsn.rs`)
The DSN parser delegates to the `url` crate for URL parsing, which is well-tested and handles edge cases properly. The parser correctly validates scheme (only http/https), requires a non-empty username, and requires a project ID.

### Session Handling (`session.rs`)
Session creation and updates are entirely generated from local application state. The `SessionFlusher` uses mutex-protected queues with a `MAX_SESSION_ITEMS = 100` cap on batch size, preventing unbounded growth. Session aggregation uses a `HashMap` with `SystemTime` keys bucketed to minute granularity, which naturally limits growth.

### Crontab Validation (`crontab_validator.rs`)
The crontab validator is simple and correct. It validates each segment against allowed numeric ranges and does not allocate based on input. The `split_whitespace` and `split` operations are bounded by the input string length.

### Custom Hex Deserialization (`macros.rs`)
The `impl_hex_de!` macro properly handles both numeric and string inputs. The `from_str_radix` and `parse` operations return errors on invalid input rather than panicking. The `as u64` cast in `visit_i64` is a widening cast and is safe.

### Timestamp Handling (`utils.rs`)
Timestamp deserialization properly uses `checked_add` when constructing `SystemTime` values and returns errors for invalid timestamps. The `timestamp_to_datetime` function correctly handles negative, infinity, and MAX float values.

---

## Summary Table

| # | Severity | Finding | File | Exploitable? |
|---|----------|---------|------|--------------|
| 1 | Medium | Integer overflow in envelope payload_end calculation | envelope.rs:636 | Yes on 32-bit (DoS) |
| 2 | Medium | JSON injection via unescaped filename in attachment header | attachment.rs:65-79 | Yes if user controls filename |
| 3 | Medium | Unescaped string interpolation in envelope item headers | envelope.rs:524-539 | Not currently (latent) |
| 4 | Low | unwrap() reachable via Finding 1 | envelope.rs:654 | Only via Finding 1 |
| 5 | Low | unwrap() on line/col number parse in stacktrace parser | parse.rs:70-72 | Requires crafted backtrace input |
| 6 | Low | Unlimited key-value pairs in auth header parsing | auth.rs:163 | Requires attacker-controlled input |
| 7 | Low | Float-to-Duration overflow in rate limiter | ratelimit.rs:28,49 | Requires malicious server |
| 8 | Low | Url::parse unwrap in DSN API URL construction | dsn.rs:99 | Edge case with exotic project IDs |

---

## Recommendations

1. **Use `checked_add` for all arithmetic on user-controlled sizes** in envelope parsing (Finding 1).
2. **Use `serde_json::to_writer` or proper JSON escaping** for attachment headers and envelope item headers (Findings 2, 3).
3. **Replace `unwrap()` with error returns** in `parse_item()` line 654 and `parse_stacktrace()` lines 70-72 (Findings 4, 5).
4. **Cap rate-limit durations** and use `checked_add` on `SystemTime` in rate limiter (Finding 7).
5. **Consider adding size limits** on deserialized collections if `Envelope::from_slice()` is ever exposed to untrusted input.
