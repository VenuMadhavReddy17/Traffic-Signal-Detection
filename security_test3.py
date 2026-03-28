#!/usr/bin/env python3
"""Security assessment - test accessible endpoints and analyze for vulnerabilities."""

import asyncio
import json
from playwright.async_api import async_playwright

BASE_URL = "https://my.staging.found.com"

async def eval_fetch(page, method, url, body=None, extra_headers=None):
    """Helper to make fetch calls via page.evaluate with proper arg count."""
    opts = {"method": method, "url": url, "body": body, "extra_headers": extra_headers or {}}
    return await page.evaluate("""
        async (opts) => {
            try {
                const fetchOpts = {method: opts.method, credentials: 'include'};
                if (opts.body) {
                    fetchOpts.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
                }
                const csrfCookie = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('csrf_token='));
                const csrfValue = csrfCookie ? csrfCookie.split('=')[1] : '';
                fetchOpts.headers = {'Content-Type': 'application/json', 'X-CSRF-Token': csrfValue, ...opts.extra_headers};
                const r = await fetch(opts.url, fetchOpts);
                const text = await r.text();
                return {status: r.status, body: text.substring(0, 2000), ct: r.headers.get('content-type')};
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

        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        """)

        page = await context.new_page()

        print("[*] Loading page...")
        await page.goto(f"{BASE_URL}/signup", wait_until="domcontentloaded", timeout=30000)
        
        for i in range(20):
            await page.wait_for_timeout(3000)
            title = await page.title()
            if "Just a moment" not in title:
                print(f"  Page loaded: {title}")
                break

        # Test 1: Public GET endpoints
        print("\n=== Test 1: Public GET Endpoints ===")
        get_endpoints = [
            "/api/data/v2/categories",
            "/api/data/business-types",
            "/api/data/v2/business-types",
            "/api/data/tax-rates",
            "/api/legal-documents",
            "/api/index",
        ]

        for ep in get_endpoints:
            resp = await eval_fetch(page, "GET", ep)
            status = resp.get('status', 'err')
            body_preview = str(resp.get('body', ''))[:200]
            print(f"  {ep}: {status} | {body_preview[:100]}")

        # Test 2: CSRF bypass - Register without CSRF token
        print("\n=== Test 2: CSRF Bypass Tests ===")
        resp = await page.evaluate("""
            async () => {
                try {
                    const r = await fetch('/api/register', {
                        method: 'POST', credentials: 'include',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({email: 'test-csrf@test.com', password: 'Test123!@#'})
                    });
                    return {status: r.status, body: (await r.text()).substring(0, 500)};
                } catch(e) { return {error: e.message}; }
            }
        """)
        print(f"  Register without CSRF: {resp.get('status', 'err')} | {str(resp.get('body', ''))[:200]}")

        resp = await page.evaluate("""
            async () => {
                try {
                    const r = await fetch('/api/register', {
                        method: 'POST', credentials: 'include',
                        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': 'invalid_token'},
                        body: JSON.stringify({email: 'test-csrf@test.com', password: 'Test123!@#'})
                    });
                    return {status: r.status, body: (await r.text()).substring(0, 500)};
                } catch(e) { return {error: e.message}; }
            }
        """)
        print(f"  Register with wrong CSRF: {resp.get('status', 'err')} | {str(resp.get('body', ''))[:200]}")

        # Test 3: Register with proper CSRF
        print("\n=== Test 3: Registration ===")
        resp = await eval_fetch(page, "POST", "/api/register", 
            body=json.dumps({"email": "sectest+bugbounty1@proton.me", "password": "TestP@ss123!Secure"}))
        print(f"  Status: {resp.get('status', 'err')}")
        print(f"  Body: {str(resp.get('body', ''))[:500]}")

        # If registration worked, try verify
        if resp.get('status') in [200, 201, 422]:
            print("\n[*] Trying OTP verification...")
            resp = await eval_fetch(page, "POST", "/api/verify-register",
                body=json.dumps({"code": "123123"}))
            print(f"  Verify: {resp.get('status', 'err')} | {str(resp.get('body', ''))[:300]}")

        # Test 4: Open redirect
        print("\n=== Test 4: Open Redirect Tests ===")
        redirect_tests = [
            "/api/redirect?url=https://evil.com",
            "/api/redirect?return_to=https://evil.com",
            "/api/redirect?next=https://evil.com",
            "/api/stripe/redirect?return_to=https://evil.com",
            "/api/stripe/redirect?return_to=//evil.com",
            "/api/stripe/redirect?return_to=https://evil.found.com.attacker.com",
        ]

        for test_url in redirect_tests:
            resp = await page.evaluate("""
                async (url) => {
                    try {
                        const r = await fetch(url, {credentials: 'include', redirect: 'manual'});
                        return {status: r.status, type: r.type, redirected: r.redirected, url: r.url};
                    } catch(e) { return {error: e.message}; }
                }
            """, test_url)
            print(f"  {test_url}: {json.dumps(resp)}")

        # Test 5: Public invoice endpoints
        print("\n=== Test 5: Public Invoice Endpoint Tests ===")
        invoice_tests = [
            "/api/public-invoice/test-id/pdf",
            "/api/public-invoice/1/pdf",
            "/api/public-invoice/1/attachment-url?invoice_attachment_id=1",
            "/api/invoice/check-identifier?identifier=test&estimate=false",
        ]

        for ep in invoice_tests:
            resp = await eval_fetch(page, "GET", ep)
            print(f"  {ep}: {resp.get('status', 'err')} | {str(resp.get('body', ''))[:200]}")

        # Test 6: Auth endpoints
        print("\n=== Test 6: Auth Endpoint Tests ===")
        auth_tests = [
            {"url": "/api/email-security-code", "body": {"email": "test@test.com"}},
            {"url": "/api/sms-security-code", "body": {"phone": "5551234567"}},
            {"url": "/api/reset-password", "body": {"email": "test@test.com"}},
            {"url": "/api/verify-code", "body": {"code": "123123"}},
            {"url": "/api/change-email/v2", "body": {"new_email": "attacker@evil.com"}},
            {"url": "/api/change-password", "body": {"old_password": "test", "new_password": "newtest"}},
        ]

        for test in auth_tests:
            resp = await eval_fetch(page, "POST", test["url"], body=json.dumps(test["body"]))
            print(f"  POST {test['url']}: {resp.get('status', 'err')} | {str(resp.get('body', ''))[:200]}")

        # Test 7: Information disclosure
        print("\n=== Test 7: Information Disclosure ===")
        info_tests = [
            "/api/nonexistent-endpoint",
            "/api/admin",
            "/api/internal",
            "/api/debug",
            "/api/health",
            "/api/status",
            "/api/version",
            "/api/config",
            "/api/graphql",
            "/api/swagger",
            "/api/docs",
        ]

        for ep in info_tests:
            resp = await eval_fetch(page, "GET", ep)
            status = resp.get('status', 'err')
            body = str(resp.get('body', ''))[:150]
            print(f"  {ep}: {status} | {body}")

        # Test 8: Debit card access token without auth
        print("\n=== Test 8: Sensitive Endpoints Without Auth ===")
        sensitive_tests = [
            {"method": "GET", "url": "/api/debit-card/access-token"},
            {"method": "GET", "url": "/api/plaid/link-token"},
            {"method": "GET", "url": "/api/debit-card/v3/all"},
            {"method": "POST", "url": "/api/upload"},
            {"method": "GET", "url": "/api/debit-card/virtual-cards-limit"},
            {"method": "POST", "url": "/api/business/email-direct-deposit-form"},
            {"method": "POST", "url": "/api/business/email-signed-bank-letter"},
            {"method": "POST", "url": "/api/linked-account/v2/link-via-account-routing"},
            {"method": "POST", "url": "/api/v2/update-name-ssn"},
            {"method": "POST", "url": "/api/v2/update-dob"},
            {"method": "POST", "url": "/api/v2/change-verified-phone"},
            {"method": "POST", "url": "/api/spend-incentive/opt-in"},
            {"method": "POST", "url": "/api/book-entry/v2/set-reason"},
        ]

        for test in sensitive_tests:
            resp = await eval_fetch(page, test["method"], test["url"], body="{}" if test["method"] == "POST" else None)
            status = resp.get('status', 'err')
            body = str(resp.get('body', ''))[:200]
            print(f"  {test['method']} {test['url']}: {status} | {body}")

        # Test 9: Security headers analysis
        print("\n=== Test 9: Security Headers ===")
        resp = await page.evaluate("""
            async () => {
                const r = await fetch('/api/data/v2/categories', {credentials: 'include'});
                return {
                    'content-type': r.headers.get('content-type'),
                    'x-content-type-options': r.headers.get('x-content-type-options'),
                    'x-frame-options': r.headers.get('x-frame-options'),
                    'strict-transport-security': r.headers.get('strict-transport-security'),
                    'content-security-policy': r.headers.get('content-security-policy'),
                    'x-xss-protection': r.headers.get('x-xss-protection'),
                    'access-control-allow-origin': r.headers.get('access-control-allow-origin'),
                    'x-request-id': r.headers.get('x-request-id'),
                };
            }
        """)
        for header, value in resp.items():
            print(f"  {header}: {value}")

        # Test 10: Cookie analysis
        print("\n=== Test 10: Cookie Security Analysis ===")
        cookies = await context.cookies()
        for cookie in cookies:
            issues = []
            if not cookie.get('secure', False):
                issues.append("Missing Secure flag")
            if not cookie.get('httpOnly', False) and cookie['name'] in ['_session_id', 'found_session_id', 'within_max_session_duration']:
                issues.append("Session cookie missing HttpOnly")
            if issues:
                print(f"  [!] {cookie['name']}: {', '.join(issues)} (domain={cookie['domain']}, secure={cookie.get('secure')}, httpOnly={cookie.get('httpOnly')}, sameSite={cookie.get('sameSite')})")
            else:
                print(f"  [OK] {cookie['name']}: secure={cookie.get('secure')}, httpOnly={cookie.get('httpOnly')}, sameSite={cookie.get('sameSite')}")

        # Test 11: CORS testing
        print("\n=== Test 11: CORS Tests ===")
        cors_tests = [
            {"origin": "https://evil.com", "url": "/api/data/v2/categories"},
            {"origin": "https://null", "url": "/api/data/v2/categories"},
            {"origin": "https://found.com.evil.com", "url": "/api/data/v2/categories"},
        ]
        
        for test in cors_tests:
            resp = await page.evaluate("""
                async (opts) => {
                    try {
                        const r = await fetch(opts.url, {
                            credentials: 'include',
                            headers: {'Origin': opts.origin}
                        });
                        return {
                            status: r.status,
                            'access-control-allow-origin': r.headers.get('access-control-allow-origin'),
                            'access-control-allow-credentials': r.headers.get('access-control-allow-credentials'),
                        };
                    } catch(e) { return {error: e.message}; }
                }
            """, test)
            print(f"  Origin={test['origin']}: {json.dumps(resp)}")

        await browser.close()
        print("\n[*] Done!")

asyncio.run(main())
