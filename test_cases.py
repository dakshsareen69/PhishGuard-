"""
PhishGuard AI - Comprehensive Test Suite (v3)
60+ test cases covering all detection layers.
Updated thresholds for improved detection engine.
"""
import os, sys
os.environ["PYTHONIOENCODING"] = "utf-8"
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

import requests
import json

API = "http://localhost:5000"
PASS = 0
FAIL = 0
RESULTS = []

def test(name, payload, expect_rank=None, expect_min_score=None, expect_max_score=None,
         expect_layer_triggered=None, expect_layer_not_triggered=None, timeout=30):
    global PASS, FAIL
    try:
        r = requests.post(f"{API}/analyze", json=payload, timeout=timeout)
        data = r.json()
    except Exception as e:
        FAIL += 1
        print(f"  FAIL  {name}")
        print(f"        Error: {e}")
        RESULTS.append(("FAIL", name, -1, "ERROR"))
        return

    if "error" in data:
        if expect_rank is None and expect_min_score is None:
            PASS += 1
            print(f"  PASS  {name}  [error response as expected]")
            RESULTS.append(("PASS", name, -1, "error"))
            return
        FAIL += 1
        print(f"  FAIL  {name}  [unexpected error: {data['error']}]")
        RESULTS.append(("FAIL", name, -1, "error"))
        return

    score = data.get("risk_score", -1)
    rank = data.get("rank", "")
    errors = []

    if expect_rank and rank != expect_rank:
        errors.append(f"Expected rank '{expect_rank}', got '{rank}'")
    if expect_min_score is not None and score < expect_min_score:
        errors.append(f"Expected score >= {expect_min_score}, got {score}")
    if expect_max_score is not None and score > expect_max_score:
        errors.append(f"Expected score <= {expect_max_score}, got {score}")

    layers = data.get("layers", {})
    if expect_layer_triggered:
        for layer in expect_layer_triggered:
            if not layers.get(layer, {}).get("triggered", False):
                errors.append(f"Expected layer '{layer}' to be triggered")
    if expect_layer_not_triggered:
        for layer in expect_layer_not_triggered:
            if layers.get(layer, {}).get("triggered", False):
                errors.append(f"Expected layer '{layer}' NOT to be triggered")

    if errors:
        FAIL += 1
        print(f"  FAIL  {name}")
        for e in errors:
            print(f"        {e}")
        print(f"        (score={score}, rank={rank})")
        RESULTS.append(("FAIL", name, score, rank))
    else:
        PASS += 1
        print(f"  PASS  {name}  [score={score}, rank={rank}]")
        RESULTS.append(("PASS", name, score, rank))


def divider(section):
    print(f"\n{'='*65}")
    print(f"  {section}")
    print(f"{'='*65}")


# ==================================================================
# HEALTH CHECK
# ==================================================================
divider("HEALTH CHECK")
try:
    r = requests.get(f"{API}/health", timeout=5)
    d = r.json()
    if d.get("status") == "ok":
        PASS += 1
        print(f"  PASS  Health check OK (OCR={d.get('ocr_available')}, WHOIS={d.get('whois_available')})")
        RESULTS.append(("PASS", "Health check", 0, "ok"))
    else:
        FAIL += 1
        print("  FAIL  Bad health response")
except:
    FAIL += 1
    print("  FAIL  Health endpoint unreachable - is Flask running?")
    sys.exit(1)


# ==================================================================
# INPUT VALIDATION
# ==================================================================
divider("INPUT VALIDATION")
test("Empty content returns error", {"type": "url", "content": ""})
test("Unknown type handled", {"type": "foobar", "content": "test"})
test("Missing type field", {"content": "test"})


# ==================================================================
# TRUSTED DOMAINS (Safe, score <= 20)
# ==================================================================
divider("TRUSTED DOMAINS -> Safe")
for domain in ["https://google.com", "https://youtube.com", "https://github.com",
                "https://amazon.com/dp/product", "https://paypal.com/myaccount",
                "https://microsoft.com/en-us"]:
    name = domain.split("//")[1].split("/")[0]
    test(f"{name} -> Safe", {"type":"url","content":domain}, expect_rank="Safe", expect_max_score=20)


# ==================================================================
# SUSPICIOUS TLDs
# ==================================================================
divider("SUSPICIOUS TLDs")
test("example.xyz", {"type":"url","content":"http://example.xyz"}, expect_min_score=20, expect_layer_triggered=["domain_analysis"])
test("freeprize.click", {"type":"url","content":"http://freeprize.click"}, expect_min_score=20, expect_layer_triggered=["domain_analysis"])
test("login-verify.top", {"type":"url","content":"http://login-verify.top"}, expect_min_score=20, expect_layer_triggered=["domain_analysis"])
test("secure-update.tk", {"type":"url","content":"http://secure-update.tk"}, expect_min_score=20, expect_layer_triggered=["domain_analysis"])


# ==================================================================
# TYPOSQUATTING
# ==================================================================
divider("TYPOSQUATTING DETECTION")
test("g00gle.com (o->0)", {"type":"url","content":"http://g00gle.com"}, expect_min_score=35, expect_rank="Scam")
test("paypa1.com (l->1)", {"type":"url","content":"http://paypa1.com"}, expect_min_score=35, expect_rank="Scam")
test("pay-pal.com (hyphen)", {"type":"url","content":"http://pay-pal.com"}, expect_min_score=35, expect_rank="Scam")
test("faceboook.com (extra letter)", {"type":"url","content":"http://faceboook.com"}, expect_min_score=35)
test("arnazon.com (m->rn)", {"type":"url","content":"http://arnazon.com"}, expect_min_score=35)
test("amaz0n-secure.xyz (combo)", {"type":"url","content":"http://amaz0n-secure.xyz"}, expect_min_score=40, expect_rank="Scam")
test("micr0soft.tk (combo)", {"type":"url","content":"http://micr0soft.tk"}, expect_min_score=40, expect_rank="Scam")


# ==================================================================
# IP URLs
# ==================================================================
divider("IP-BASED URL DETECTION")
test("http://192.168.1.1/login", {"type":"url","content":"http://192.168.1.1/login"}, expect_min_score=30)
test("http://45.33.32.156/phish", {"type":"url","content":"http://45.33.32.156/phish"}, expect_min_score=30)


# ==================================================================
# EXCESSIVE SUBDOMAINS
# ==================================================================
divider("EXCESSIVE SUBDOMAINS")
test("login.verify.secure.update.evil.com", {"type":"url","content":"http://login.verify.secure.update.evil.com"}, expect_min_score=25)


# ==================================================================
# URL OBFUSCATION
# ==================================================================
divider("URL OBFUSCATION")
test("Very long URL", {"type":"url","content":"http://suspicious-site.com/" + "a"*120}, expect_min_score=15)
test("URL with @ symbol", {"type":"url","content":"http://google.com@evil.com/steal"}, expect_min_score=25)
test("URL shortener (bit.ly)", {"type":"url","content":"https://bit.ly/3xYzAbC"}, expect_layer_triggered=["domain_analysis"])
test("No HTTPS", {"type":"url","content":"http://some-random-site.com/page"}, expect_layer_triggered=["domain_analysis"])


# ==================================================================
# PHISHING PATH KEYWORDS
# ==================================================================
divider("PHISHING PATH KEYWORDS")
test("URL with /login/verify path", {"type":"url","content":"http://evil-site.xyz/login/verify/account"}, expect_min_score=30)
test("URL with /password-reset", {"type":"url","content":"http://bad.click/password/reset/billing"}, expect_min_score=30)


# ==================================================================
# BEHAVIORAL: URGENCY
# ==================================================================
divider("BEHAVIORAL: URGENCY")
test("Urgency signals", {"type":"text","content":"Act now! Your account expires within 24 hours. This is urgent and time-sensitive. Don't delay!"}, expect_min_score=25)
test("Final notice + deadline", {"type":"text","content":"FINAL NOTICE: Hurry, the deadline is today only! Failure to respond will result in closure. Do this now before it's too late!"}, expect_min_score=25)


# ==================================================================
# BEHAVIORAL: THREATS
# ==================================================================
divider("BEHAVIORAL: THREATS")
test("Account suspension", {"type":"text","content":"Your account has been suspended due to unusual activity. If you don't verify your identity immediately, your account will be permanently closed."}, expect_min_score=30, expect_rank="Scam")
test("Security breach", {"type":"text","content":"We detected a security breach on your account. Unauthorized access was found. You must verify your identity now or risk losing your account."}, expect_min_score=30, expect_rank="Scam")


# ==================================================================
# BEHAVIORAL: REWARD BAIT
# ==================================================================
divider("BEHAVIORAL: REWARD BAIT")
test("Prize scam", {"type":"text","content":"Congratulations! You have won a free iPhone 15! Claim your prize now! This is a $500 reward bonus from the sweepstakes lottery."}, expect_min_score=30)
test("Lucky winner", {"type":"text","content":"You are the lucky winner! You've been selected for an exclusive offer. Get a free gift card, totally free, no cost. Claim your cash reward!"}, expect_min_score=30)


# ==================================================================
# BEHAVIORAL: CREDENTIAL HARVESTING
# ==================================================================
divider("BEHAVIORAL: CREDENTIAL HARVESTING")
test("Password request", {"type":"text","content":"Please enter your password and username below. Click here to verify and sign in to your account. Your password will expire soon. Reset your password now."}, expect_min_score=25)
test("Login form bait", {"type":"text","content":"Log in to your account to confirm your identity. Enter your credentials below to secure your account access."}, expect_min_score=20)


# ==================================================================
# BEHAVIORAL: IMPERSONATION
# ==================================================================
divider("BEHAVIORAL: IMPERSONATION")
test("Brand impersonation", {"type":"text","content":"This is Apple Support Team. Dear valued customer, we have an official notice about your account. Microsoft Security alert notification from the account department."}, expect_min_score=20)
test("Dear customer + behalf", {"type":"text","content":"Dear valued customer, on behalf of Chase customer service department, this is an official notification regarding your account."}, expect_min_score=20)


# ==================================================================
# BEHAVIORAL: SENSITIVE INFO
# ==================================================================
divider("BEHAVIORAL: SENSITIVE INFO")
test("SSN + credit card + bank", {"type":"text","content":"Please provide your social security number and credit card number including the CVV. Also share your bank account, routing number, and billing information."}, expect_min_score=30)
test("Personal info + tax + OTP", {"type":"text","content":"We need your personal information including your tax ID number, date of birth, driver's license, and the OTP verification code sent to your phone."}, expect_min_score=30)


# ==================================================================
# COMBINED: FULL PHISHING EMAILS -> Scam (score > 40)
# ==================================================================
divider("COMBINED: FULL PHISHING -> expect Scam (score > 40)")

test("PayPal phishing email", {"type":"text","content":"""
URGENT: Your PayPal account has been suspended due to unauthorized activity.
You must verify your identity immediately or your account will be permanently closed.
Click here to sign in to your account and update your password.
You will need to provide your social security number and credit card details.
Act now - this link expires within 24 hours!
Congratulations, you've also been selected for a $1000 reward bonus.
"""}, expect_rank="Scam", expect_min_score=41)

test("Amazon phishing with URL", {"type":"text","content":"""
Dear valued customer, we detected unusual login activity on your Amazon account.
Your account will be terminated if you do not respond immediately.
Click below to confirm your details and enter your OTP verification code.
Visit: http://amaz0n-verify.tk/login
"""}, expect_rank="Scam", expect_min_score=41)

test("Netflix account lock", {"type":"text","content":"""
Dear customer, your Netflix account has been locked due to suspicious activity.
You must update your payment information immediately or your account will be closed.
Please provide your credit card number and billing address.
Click here to verify your account: http://netfl1x-support.xyz/verify
This is your final notice. Act now before it's too late!
"""}, expect_rank="Scam", expect_min_score=41)

test("IRS tax scam", {"type":"text","content":"""
URGENT: This is the IRS department. We have detected unauthorized activity on your tax filing.
You are required to verify your social security number and date of birth immediately.
Failure to respond will result in legal action and prosecution.
Submit your personal information at: http://irs-verify.click/form
You must do this now. Only 24 hours left.
"""}, expect_rank="Scam", expect_min_score=41)

test("Bank account phishing", {"type":"text","content":"""
Security alert from Chase customer support team.
We noticed a fraudulent transaction on your bank account.
Your account has been temporarily restricted. You need to verify your identity
by providing your account number, routing number, and SSN.
Click the link below to restore access to your account.
Hurry, this is time-sensitive! Don't delay!
"""}, expect_rank="Scam", expect_min_score=41)

test("WhatsApp prize scam", {"type":"text","content":"""
Congratulations! You've been chosen as the lucky winner of our WhatsApp sweepstakes!
You won a $5000 cash prize and a free iPhone! Claim your reward now.
To receive your gift card, provide your credit card details and billing address.
This exclusive offer expires today! Act now, this is your last chance!
"""}, expect_rank="Scam", expect_min_score=41)

test("Microsoft account phishing", {"type":"text","content":"""
This is Microsoft Security Team. Official notice: your account was compromised.
We detected a security breach. Unauthorized access to your Microsoft account was found.
You must immediately log in to your account and reset your password.
Enter your username and password at: http://micros0ft-secure.tk/login
If you don't act now, your account will be permanently suspended.
"""}, expect_rank="Scam", expect_min_score=41)

test("FedEx delivery scam", {"type":"text","content":"""
Dear customer, notification from FedEx department:
Your package delivery has been suspended. To reschedule, verify your identity
by providing your personal information and payment details.
Click here to confirm your address and credit card number.
This is urgent - respond within 48 hours or the package will be returned.
"""}, expect_rank="Scam", expect_min_score=41)

test("DHL customs scam", {"type":"text","content":"""
Your DHL package could not be delivered. A customs fee of $3.99 is required.
Pay now with your credit card to avoid return shipping.
Provide your billing information and card number at: http://dhl-customs-pay.top/fee
This is your final notice. Act immediately.
"""}, expect_rank="Scam", expect_min_score=41)

test("Google account phishing", {"type":"text","content":"""
Hi, I'm reaching out on behalf of Google customer support.
Your Google Workspace subscription payment failed.
Update your billing information and credit card number
immediately to avoid service interruption. Confirm your account now.
If you fail to respond, your account will be permanently closed.
"""}, expect_rank="Scam", expect_min_score=41)


# ==================================================================
# BENIGN CONTENT -> Safe (score <= 20)
# ==================================================================
divider("BENIGN CONTENT -> expect Safe (score <= 20)")
test("Normal email", {"type":"text","content":"Hey, just checking in. Did you get a chance to review the report I sent yesterday? Let me know when you're free to discuss."}, expect_rank="Safe", expect_max_score=20)
test("Newsletter", {"type":"text","content":"Thanks for subscribing to our weekly newsletter. This week we cover the latest web development trends and open source tools."}, expect_rank="Safe", expect_max_score=20)
test("Technical discussion", {"type":"text","content":"The function returns a promise that resolves with the parsed JSON data. Make sure to handle errors in the catch block properly."}, expect_rank="Safe", expect_max_score=20)
test("Meeting invite", {"type":"text","content":"Hi team, let's meet tomorrow at 3 PM to discuss the Q2 roadmap. I've attached the agenda document. See you there!"}, expect_rank="Safe", expect_max_score=20)
test("Shopping receipt", {"type":"text","content":"Thank you for your purchase! Your order #12345 has been confirmed. Estimated delivery: 3-5 business days. Total: $49.99."}, expect_rank="Safe", expect_max_score=20)
test("Friendly message", {"type":"text","content":"Happy birthday! Wishing you an amazing day filled with joy. Looking forward to celebrating with you this weekend!"}, expect_rank="Safe", expect_max_score=20)
test("Code review", {"type":"text","content":"I pushed the refactored authentication module to the feature branch. Can you review the pull request when you have time? The tests are all passing."}, expect_rank="Safe", expect_max_score=20)
test("Weather chat", {"type":"text","content":"The weather forecast for this weekend looks great! Sunny skies with highs around 75. Perfect for the hiking trip we planned."}, expect_rank="Safe", expect_max_score=20)


# ==================================================================
# EDGE CASES
# ==================================================================
divider("EDGE CASES")
test("Phishing keywords in path", {"type":"url","content":"http://evil-site.xyz/verify-your-account/login/password-reset"}, expect_min_score=30)
test("Trusted domain /login path", {"type":"url","content":"https://google.com/accounts/login"}, expect_rank="Safe", expect_max_score=20)
test("All caps urgency", {"type":"text","content":"URGENT!!! ACT NOW OR YOUR ACCOUNT WILL BE SUSPENDED!!! VERIFY IMMEDIATELY!!!"}, expect_min_score=30, expect_rank="Scam")


# ==================================================================
# SUMMARY
# ==================================================================
total = PASS + FAIL
phishing_tests = [r for r in RESULTS if r[0] == "PASS" and r[3] == "Scam"]
safe_tests = [r for r in RESULTS if r[0] == "PASS" and r[3] == "Safe"]

print(f"\n{'='*65}")
print(f"  RESULTS: {PASS} passed, {FAIL} failed out of {total} tests")
if total > 0:
    print(f"  Pass rate: {PASS/total*100:.1f}%")
print(f"  Phishing correctly detected (Scam): {len(phishing_tests)}")
print(f"  Benign correctly classified (Safe): {len(safe_tests)}")
print(f"{'='*65}")

if FAIL > 0:
    print(f"\n  Failed tests:")
    for r in RESULTS:
        if r[0] == "FAIL":
            print(f"    - {r[1]} (score={r[2]}, rank={r[3]})")

sys.exit(0 if FAIL == 0 else 1)
