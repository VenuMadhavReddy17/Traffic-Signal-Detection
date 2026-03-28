#!/usr/bin/env python3
"""
Security testing script for Found staging application.
Uses Playwright with stealth to bypass Cloudflare and interact with the app.
"""

import asyncio
import json
import time
import os
from playwright.async_api import async_playwright
from playwright_stealth import Stealth

BASE_URL = "https://my.staging.found.com"
TEST_EMAIL = f"sectest+{int(time.time())}@protonmail.com"
OTP_CODE = "123123"
PHONE_NUMBER = "5551234567"

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-blink-features=AutomationControlled',
            ]
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720},
            locale="en-US",
            timezone_id="America/New_York",
        )
        
        stealth = Stealth()
        page = await context.new_page()
        await stealth.apply_stealth_async(page)
        
        all_api_responses = []
        
        async def on_response(response):
            url = response.url
            if "/api/" in url or "/graphql" in url:
                try:
                    body = await response.text()
                    entry = {
                        "status": response.status,
                        "url": url,
                        "body": body[:3000]
                    }
                    all_api_responses.append(entry)
                    print(f"[RESP] {response.status} {url} -> {body[:300]}")
                except:
                    print(f"[RESP] {response.status} {url} -> (no body)")
        
        page.on("response", lambda resp: asyncio.ensure_future(on_response(resp)))
        
        # Step 1: Navigate to login page
        print(f"[*] Navigating to {BASE_URL}/login")
        try:
            await page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            print(f"[!] Navigation error: {e}")
        
        # Wait for CF to pass
        print("[*] Waiting for Cloudflare challenge...")
        await page.wait_for_timeout(10000)
        
        print(f"[*] Page title: {await page.title()}")
        print(f"[*] Page URL: {page.url}")
        
        await page.screenshot(path="/tmp/page1.png")
        
        # Check if we passed CF
        title = await page.title()
        if "moment" in title.lower() or "challenge" in title.lower():
            print("[!] Still on Cloudflare challenge, waiting longer...")
            await page.wait_for_timeout(15000)
            title = await page.title()
            print(f"[*] Title after waiting: {title}")
            await page.screenshot(path="/tmp/page1b.png")
        
        # Get cookies
        cookies = await context.cookies()
        cookie_info = [{'name': c['name'], 'domain': c['domain'], 'httpOnly': c['httpOnly'], 'secure': c['secure'], 'sameSite': c.get('sameSite', 'N/A'), 'path': c['path']} for c in cookies]
        print(f"[*] Cookies: {json.dumps(cookie_info, indent=2)}")
        
        # Save cookies for later reuse
        with open("/tmp/cookies.json", "w") as f:
            json.dump(cookies, f, indent=2)
        
        # Test API from the page context (uses browser cookies)
        print("\n[*] Testing API endpoints from browser context...")
        
        endpoints = [
            ("/api/data/business-types", "GET"),
            ("/api/data/v2/business-types", "GET"),
            ("/api/data/v2/categories", "GET"),
            ("/api/data/tax-rates", "GET"),
            ("/api/legal-documents", "GET"),
            ("/api/minimum-app-version", "GET"),
            ("/api/subscription-features", "GET"),
            ("/api/debit-card/v3/all", "GET"),
            ("/api/v2/inbox", "GET"),
            ("/api/account-number", "GET"),
            ("/api/index", "GET"),
        ]
        
        for url, method in endpoints:
            try:
                result = await page.evaluate(f"""
                    async () => {{
                        try {{
                            const r = await fetch('{url}', {{
                                method: '{method}',
                                credentials: 'include',
                                headers: {{'Accept': 'application/json'}}
                            }});
                            const t = await r.text();
                            return {{s: r.status, b: t.substring(0, 2000), h: Object.fromEntries(r.headers.entries())}};
                        }} catch(e) {{
                            return {{e: e.message}};
                        }}
                    }}
                """)
                print(f"[*] {method} {url} -> Status: {result.get('s')}, Body: {str(result.get('b', ''))[:500]}")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        # Try register
        print(f"\n[*] Registering: {TEST_EMAIL}")
        reg_result = await page.evaluate(f"""
            async () => {{
                try {{
                    const r = await fetch('/api/register', {{
                        method: 'POST',
                        credentials: 'include',
                        headers: {{'Accept': 'application/json', 'Content-Type': 'application/json'}},
                        body: JSON.stringify({{email: '{TEST_EMAIL}', password: 'SecurePass123!@#'}})
                    }});
                    const t = await r.text();
                    return {{s: r.status, b: t.substring(0, 3000), h: Object.fromEntries(r.headers.entries())}};
                }} catch(e) {{
                    return {{e: e.message}};
                }}
            }}
        """)
        print(f"[*] Register: {json.dumps(reg_result)[:2000]}")
        
        # If registered, verify with OTP
        if reg_result.get("s") in [200, 201]:
            print(f"\n[*] Verifying with OTP: {OTP_CODE}")
            verify_result = await page.evaluate(f"""
                async () => {{
                    try {{
                        const r = await fetch('/api/verify-register', {{
                            method: 'POST',
                            credentials: 'include',
                            headers: {{'Accept': 'application/json', 'Content-Type': 'application/json'}},
                            body: JSON.stringify({{code: '{OTP_CODE}'}})
                        }});
                        const t = await r.text();
                        return {{s: r.status, b: t.substring(0, 3000)}};
                    }} catch(e) {{
                        return {{e: e.message}};
                    }}
                }}
            """)
            print(f"[*] Verify: {json.dumps(verify_result)[:2000]}")
            
            # If verified, get the full user data
            if verify_result.get("s") in [200, 201]:
                print("\n[*] Authenticated! Testing authenticated endpoints...")
                
                index_result = await page.evaluate("""
                    async () => {
                        try {
                            const r = await fetch('/api/index', {
                                credentials: 'include',
                                headers: {'Accept': 'application/json'}
                            });
                            const t = await r.text();
                            return {s: r.status, b: t.substring(0, 5000)};
                        } catch(e) {
                            return {e: e.message};
                        }
                    }
                """)
                print(f"[*] /api/index: {json.dumps(index_result)[:5000]}")
                
                # Test GraphQL introspection
                print("\n[*] Testing GraphQL introspection...")
                gql_result = await page.evaluate("""
                    async () => {
                        try {
                            const r = await fetch('/graphql', {
                                method: 'POST',
                                credentials: 'include',
                                headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
                                body: JSON.stringify({query: '{ __schema { queryType { name } mutationType { name } types { name kind description fields { name type { name kind } } } } }'})
                            });
                            const t = await r.text();
                            return {s: r.status, b: t.substring(0, 10000)};
                        } catch(e) {
                            return {e: e.message};
                        }
                    }
                """)
                print(f"[*] GraphQL introspection: {json.dumps(gql_result)[:5000]}")
        
        # Test security-sensitive scenarios
        print("\n[*] Testing for CSRF token presence...")
        csrf_result = await page.evaluate("""
            async () => {
                const meta = document.querySelector('meta[name="csrf-token"]');
                const csrfCookie = document.cookie.split(';').find(c => c.trim().startsWith('csrf') || c.trim().startsWith('_csrf'));
                return {
                    meta_csrf: meta ? meta.getAttribute('content') : null,
                    csrf_cookie: csrfCookie || null,
                    all_cookies: document.cookie
                };
            }
        """)
        print(f"[*] CSRF: {json.dumps(csrf_result)[:1000]}")
        
        # Test password reset for user enumeration
        print("\n[*] Testing password reset for user enumeration...")
        for email in ["nonexistent@example.com", "test@found.com"]:
            reset_result = await page.evaluate(f"""
                async () => {{
                    try {{
                        const r = await fetch('/api/reset-password', {{
                            method: 'POST',
                            credentials: 'include',
                            headers: {{'Accept': 'application/json', 'Content-Type': 'application/json'}},
                            body: JSON.stringify({{email: '{email}'}})
                        }});
                        const t = await r.text();
                        return {{s: r.status, b: t.substring(0, 1000)}};
                    }} catch(e) {{
                        return {{e: e.message}};
                    }}
                }}
            """)
            print(f"[*] Reset {email}: {json.dumps(reset_result)[:500]}")
        
        # Test for open redirect
        print("\n[*] Testing for open redirect on /api/redirect...")
        redirect_result = await page.evaluate("""
            async () => {
                try {
                    const r = await fetch('/api/redirect?url=https://evil.com', {
                        method: 'GET',
                        credentials: 'include',
                        redirect: 'manual'
                    });
                    return {s: r.status, type: r.type, redirected: r.redirected, url: r.url};
                } catch(e) {
                    return {e: e.message};
                }
            }
        """)
        print(f"[*] Open redirect test: {json.dumps(redirect_result)[:500]}")
        
        # Save all API responses
        with open("/tmp/all_api_responses.json", "w") as f:
            json.dump(all_api_responses, f, indent=2)
        
        print(f"\n[*] Total API responses captured: {len(all_api_responses)}")
        print("[*] Done!")
        
        await browser.close()

asyncio.run(main())
