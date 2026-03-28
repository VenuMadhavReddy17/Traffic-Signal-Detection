#!/usr/bin/env python3
"""
Security testing script for Found staging - Phase 3.
Navigate to signup page via browser, handle Cloudflare, register, and test.
"""

import asyncio
import json
import time
from playwright.async_api import async_playwright
from playwright_stealth import Stealth

BASE_URL = "https://my.staging.found.com"

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-blink-features=AutomationControlled']
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720},
            locale="en-US",
        )
        
        stealth = Stealth()
        page = await context.new_page()
        await stealth.apply_stealth_async(page)
        
        results = {}
        
        # Navigate to a page that doesn't trigger Cloudflare POST block
        print("[*] Loading data endpoint to establish session...")
        await page.goto(f"{BASE_URL}/api/data/business-types", wait_until="domcontentloaded", timeout=15000)
        await page.wait_for_timeout(3000)
        
        # Get CSRF from cookies
        cookies = await context.cookies()
        csrf = None
        session_id = None
        for c in cookies:
            if c['name'] == 'csrf_token':
                csrf = c['value']
            if c['name'] == '_session_id':
                session_id = c['value']
        print(f"[*] CSRF: {csrf}")
        print(f"[*] Session ID cookie present: {session_id is not None}")
        
        # Navigate to get more cookies
        resp = await page.goto(f"{BASE_URL}/api/minimum-app-version", wait_until="domcontentloaded", timeout=15000)
        body = await resp.text() if resp else ""
        print(f"[*] Min app version: {body[:200]}")
        
        cookies = await context.cookies()
        for c in cookies:
            if c['name'] == 'csrf_token':
                csrf = c['value']
        print(f"[*] CSRF updated: {csrf}")
        
        # Now try to POST with browser context using fetch API
        print("\n[*] Attempting registration via browser fetch...")
        
        email = f"sectest+{int(time.time())}@protonmail.com"
        print(f"[*] Email: {email}")
        
        # Navigate to the login page first to get proper CF clearance
        print("[*] Loading login page to get CF clearance...")
        await page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(8000)
        
        title = await page.title()
        print(f"[*] Title: {title}")
        
        if "moment" in title.lower():
            print("[*] Cloudflare challenge present, waiting...")
            await page.wait_for_timeout(10000)
            title = await page.title()
            print(f"[*] Title after wait: {title}")
        
        # Try registration from the browser context
        reg_js = f"""
            async () => {{
                try {{
                    const csrfMatch = document.cookie.match(/csrf_token=([^;]+)/);
                    const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
                    
                    const r = await fetch('/api/register', {{
                        method: 'POST',
                        credentials: 'include',
                        headers: {{
                            'Accept': 'application/json',
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': csrf
                        }},
                        body: JSON.stringify({{
                            email: '{email}',
                            password: 'SecurePass123!@#'
                        }})
                    }});
                    const t = await r.text();
                    return {{status: r.status, body: t.substring(0, 3000), csrf: csrf}};
                }} catch(e) {{
                    return {{error: e.message}};
                }}
            }}
        """
        
        reg_result = await page.evaluate(reg_js)
        print(f"[*] Register: {json.dumps(reg_result)[:2000]}")
        
        results['register'] = reg_result
        
        if reg_result.get('status') == 200:
            # Try to parse register response
            try:
                reg_data = json.loads(reg_result['body'])
                print(f"[*] Register data keys: {list(reg_data.keys()) if isinstance(reg_data, dict) else 'not dict'}")
            except:
                pass
            
            # Verify OTP
            print("\n[*] Verifying OTP...")
            verify_result = await page.evaluate("""
                async () => {
                    try {
                        const csrfMatch = document.cookie.match(/csrf_token=([^;]+)/);
                        const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
                        const r = await fetch('/api/verify-register', {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json',
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': csrf
                            },
                            body: JSON.stringify({code: '123123'})
                        });
                        const t = await r.text();
                        return {status: r.status, body: t.substring(0, 5000)};
                    } catch(e) {
                        return {error: e.message};
                    }
                }
            """)
            print(f"[*] Verify: {json.dumps(verify_result)[:3000]}")
            results['verify'] = verify_result
            
            if verify_result.get('status') == 200:
                print("\n[*] AUTHENTICATED! Running vulnerability tests...")
                
                # Get user data
                index_result = await page.evaluate("""
                    async () => {
                        try {
                            const csrfMatch = document.cookie.match(/csrf_token=([^;]+)/);
                            const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
                            const r = await fetch('/api/index', {
                                credentials: 'include',
                                headers: {
                                    'Accept': 'application/json',
                                    'X-CSRF-Token': csrf
                                }
                            });
                            const t = await r.text();
                            return {status: r.status, body: t.substring(0, 10000)};
                        } catch(e) {
                            return {error: e.message};
                        }
                    }
                """)
                print(f"[*] Index: {json.dumps(index_result)[:5000]}")
                results['index'] = index_result
                
                # VULNERABILITY TEST: Check if business_id parameter allows accessing other businesses
                # This is the IDOR test
                test_endpoints = [
                    "/api/business",
                    "/api/account-number",
                    "/api/debit-card/v3/all",
                    "/api/subscriptions",
                    "/api/subscription-features",
                    "/api/v2/inbox",
                    "/api/risk/features-enabled",
                    "/api/pockets",
                    "/api/custom-category",
                    "/api/business/events",
                    "/api/external-transaction-account",
                ]
                
                for ep in test_endpoints:
                    try:
                        r = await page.evaluate(f"""
                            async () => {{
                                try {{
                                    const csrfMatch = document.cookie.match(/csrf_token=([^;]+)/);
                                    const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
                                    const r = await fetch('{ep}', {{
                                        credentials: 'include',
                                        headers: {{
                                            'Accept': 'application/json',
                                            'X-CSRF-Token': csrf
                                        }}
                                    }});
                                    const t = await r.text();
                                    return {{status: r.status, body: t.substring(0, 1000)}};
                                }} catch(e) {{
                                    return {{error: e.message}};
                                }}
                            }}
                        """)
                        print(f"[*] GET {ep} -> {r.get('status')}: {str(r.get('body', ''))[:200]}")
                        results[ep] = r
                    except Exception as e:
                        print(f"[!] Error on {ep}: {e}")
        
        # Whether or not we got authed, still test these
        # VULNERABILITY: Information disclosure in error messages
        print("\n[*] Testing error response information disclosure...")
        error_tests = [
            ("/api/business/non-existent-endpoint", "GET"),
            ("/api/upload", "GET"),
            ("/api/v2/business-contact/invalid-id", "GET"),
        ]
        
        for url, method in error_tests:
            try:
                r = await page.evaluate(f"""
                    async () => {{
                        try {{
                            const r = await fetch('{url}', {{
                                method: '{method}',
                                credentials: 'include',
                                headers: {{'Accept': 'application/json'}}
                            }});
                            const t = await r.text();
                            return {{status: r.status, body: t.substring(0, 500)}};
                        }} catch(e) {{
                            return {{error: e.message}};
                        }}
                    }}
                """)
                print(f"[*] {method} {url} -> {r.get('status')}: {str(r.get('body',''))[:300]}")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        # Save all results
        with open("/tmp/security_results.json", "w") as f:
            json.dump(results, f, indent=2, default=str)
        
        # Get final cookie state
        cookies = await context.cookies()
        with open("/tmp/final_cookies.json", "w") as f:
            json.dump(cookies, f, indent=2)
        
        cookie_security = []
        for c in cookies:
            issues = []
            if not c.get('secure') and c['name'] not in ['_found_avt', '_dd_s']:
                issues.append("Missing Secure flag")
            if not c.get('httpOnly') and c['name'] in ['_session_id', 'found_session_id']:
                issues.append("Missing HttpOnly flag")
            if c.get('sameSite') == 'None' and c['name'] not in ['cf_clearance', '__cf_bm']:
                issues.append("SameSite=None")
            if issues:
                cookie_security.append({"name": c['name'], "issues": issues, "secure": c.get('secure'), "httpOnly": c.get('httpOnly'), "sameSite": c.get('sameSite')})
        
        print(f"\n[*] Cookie security issues: {json.dumps(cookie_security, indent=2)}")
        
        await browser.close()
        print("[*] Done!")

asyncio.run(main())
