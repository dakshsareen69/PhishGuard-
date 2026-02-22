"""
PhishGuard AI — Flask Backend
Multi-layer phishing detection API.
No data stored. All analysis is in-memory and discarded after each response.
"""
from __future__ import annotations
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
import re
import io
import sys
import base64
import logging
import threading
import time
from datetime import datetime
from urllib.parse import urlparse, unquote, quote

import requests
import tldextract
from flask import Flask, request, jsonify
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Try optional imports — graceful fallback if unavailable
# ---------------------------------------------------------------------------
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging setup — colored console output
# ---------------------------------------------------------------------------
class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    BOLD = '\033[1m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.msg = f"{color}{self.BOLD}[{record.levelname}]{self.RESET} {record.msg}"
        return super().format(record)

logger = logging.getLogger("phishguard")
logger.setLevel(logging.DEBUG)
# Fix Windows console encoding for emoji in log messages
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColorFormatter('%(asctime)s %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(handler)

# ---------------------------------------------------------------------------
# Flask App
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app)

# Serve index.html from the same folder
@app.route("/")
def serve_index():
    return app.send_static_file("index.html")

app.static_folder = "."
app.static_url_path = ""

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
TRUSTED_BRANDS = [
    "google", "facebook", "apple", "microsoft", "amazon", "paypal",
    "netflix", "instagram", "whatsapp", "twitter", "linkedin", "youtube",
    "gmail", "outlook", "yahoo", "ebay", "dropbox", "chase", "wellsfargo",
    "bankofamerica", "citibank", "irs", "gov", "fedex", "dhl", "ups",
    "usps", "spotify", "snapchat", "tiktok", "pinterest", "uber",
    "airbnb", "coinbase", "binance", "stripe", "venmo", "zelle"
]

TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "apple.com", "microsoft.com", "amazon.com",
    "paypal.com", "netflix.com", "instagram.com", "whatsapp.com", "twitter.com",
    "linkedin.com", "youtube.com", "gmail.com", "outlook.com", "yahoo.com",
    "ebay.com", "dropbox.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "citibank.com", "fedex.com", "dhl.com", "ups.com",
    "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org",
    "spotify.com", "uber.com", "airbnb.com", "stripe.com", "x.com"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".gq", ".ml",
    ".cf", ".tk", ".ga", ".pw", ".cc", ".info", ".biz", ".online",
    ".site", ".website", ".space", ".fun", ".icu", ".vip", ".live",
    ".stream", ".download", ".win", ".racing", ".date", ".review",
    ".loan", ".trade", ".bid", ".accountant", ".science", ".party",
    ".cricket", ".faith", ".zip", ".mov", ".buzz", ".rest", ".sbs"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "v.gd", "qr.ae", "yourls.org"
]

CHAR_SUBS = {"a": "@", "o": "0", "i": "1", "l": "1", "e": "3", "s": "5"}

# Phishing keywords commonly found in malicious URL paths
PHISHING_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "confirm", "secure", "security", "update", "account", "password",
    "reset", "unlock", "restore", "billing", "payment", "wallet",
    "authenticate", "validate", "suspended", "reactivate", "recover",
    "banking", "credential", "identity", "ssn", "webscr", "cmd=login"
]

# ---------------------------------------------------------------------------
# LAYER 1 — Live Threat Intelligence
# ---------------------------------------------------------------------------
OPENPHISH_FEED: list[str] = []
_openphish_lock = threading.Lock()


def _load_openphish():
    """Background loader for OpenPhish feed (refreshes every 30 min)."""
    global OPENPHISH_FEED
    while True:
        try:
            r = requests.get("https://openphish.com/feed.txt", timeout=8)
            if r.status_code == 200:
                with _openphish_lock:
                    OPENPHISH_FEED = r.text.strip().splitlines()
                logger.info(f"OpenPhish feed loaded: {len(OPENPHISH_FEED)} entries")
        except Exception as exc:
            logger.warning(f"OpenPhish fetch failed: {exc}")
        time.sleep(1800)  # 30 minutes


def check_urlhaus(url: str):
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=5
        )
        data = r.json()
        if data.get("query_status") == "is_blacklisted":
            return True, "URLhaus", "Known malicious URL (blacklisted)"
    except Exception:
        pass
    return False, None, None


def check_phishtank(url: str):
    try:
        encoded = quote(url, safe="")
        r = requests.get(
            f"https://checkurl.phishtank.com/checkurl/?url={encoded}&format=json",
            timeout=5
        )
        data = r.json()
        results = data.get("results", {})
        if results.get("in_database") and results.get("valid"):
            return True, "PhishTank", "Confirmed phishing page in PhishTank database"
    except Exception:
        pass
    return False, None, None


def check_openphish(url: str):
    with _openphish_lock:
        feed = list(OPENPHISH_FEED)
    for entry in feed:
        entry = entry.strip()
        if entry and (entry in url or url in entry):
            return True, "OpenPhish", "URL found in OpenPhish live feed"
    return False, None, None


def run_threat_intel(url: str):
    """Check all threat-intel feeds. Returns dict with results."""
    sources_checked = []
    for checker in [check_urlhaus, check_phishtank, check_openphish]:
        hit, source, detail = checker(url)
        if hit:
            logger.info(f"  ⚡ Threat intel HIT: {source} — {detail}")
            return {
                "triggered": True,
                "source": source,
                "detail": detail,
                "sources_checked": sources_checked + [source]
            }
        if source:
            sources_checked.append(source)
    return {
        "triggered": False,
        "source": None,
        "detail": "Not found in any threat intelligence feed",
        "sources_checked": ["URLhaus", "PhishTank", "OpenPhish"]
    }


# ---------------------------------------------------------------------------
# LAYER 2 — Domain Risk Analysis
# ---------------------------------------------------------------------------
def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost
            ))
        prev_row = curr_row
    return prev_row[-1]


def check_typosquatting(domain: str) -> tuple[bool, list[str]]:
    signals = []
    domain_lower = domain.lower()

    # Build all normalized variants of the domain
    normalised = domain_lower
    for orig, sub in CHAR_SUBS.items():
        normalised = normalised.replace(sub, orig)

    dehyphenated = domain_lower.replace("-", "")

    dehy_normalised = dehyphenated
    for orig, sub in CHAR_SUBS.items():
        dehy_normalised = dehy_normalised.replace(sub, orig)

    variants = set([domain_lower, normalised, dehyphenated, dehy_normalised])

    for brand in TRUSTED_BRANDS:
        if domain_lower == brand:
            continue

        for v in variants:
            # Exact or near-exact match
            dist = _levenshtein(v, brand)
            if dist <= 2:
                if v != domain_lower:
                    signals.append(f"Character/formatting trick detected — impersonates '{brand}'")
                else:
                    signals.append(f"Domain '{domain_lower}' looks like '{brand}' (typosquatting)")
                break

            # Brand used as prefix (e.g. amaz0n-secure, paypal-verify)
            if v.startswith(brand) or (len(brand) >= 4 and brand in v):
                signals.append(f"Domain contains brand name '{brand}' — possible impersonation")
                break

        if signals:
            break

    return bool(signals), signals


def check_subdomain_abuse(parsed_url) -> tuple[bool, list[str]]:
    signals = []
    hostname = parsed_url.hostname or ""
    ext = tldextract.extract(hostname)
    subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []
    for brand in TRUSTED_BRANDS:
        for part in subdomain_parts:
            if brand in part.lower() and ext.domain.lower() != brand:
                signals.append(
                    f"Brand '{brand}' used as subdomain on '{ext.registered_domain}' — likely abuse"
                )
    return bool(signals), signals


def is_ip_url(url: str) -> bool:
    return bool(re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', url))


def get_domain_age_days(domain: str):
    if not WHOIS_AVAILABLE:
        return None
    try:
        w = python_whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            return (datetime.now() - creation).days
    except Exception:
        pass
    return None


def count_phishing_path_keywords(url: str) -> tuple[int, list[str]]:
    """Count phishing-related keywords in the URL path/query."""
    try:
        parsed = urlparse(url)
        path_query = (parsed.path + "?" + (parsed.query or "")).lower()
    except Exception:
        return 0, []
    found = []
    for kw in PHISHING_PATH_KEYWORDS:
        if kw in path_query:
            found.append(kw)
    return len(found), found


def run_domain_analysis(url: str):
    """Analyse domain-level risk factors. Returns dict of signals."""
    signals = {}
    signal_details: list[str] = []

    try:
        parsed = urlparse(url)
    except Exception:
        return {"signals": signal_details, "flags": signals}

    ext = tldextract.extract(url)
    domain = ext.domain
    registered = ext.registered_domain
    hostname = parsed.hostname or ""

    # 2a — Typosquatting
    hit, msgs = check_typosquatting(domain)
    if hit:
        signals["typosquatting"] = True
        signal_details.extend(msgs)

    # Subdomain abuse
    hit, msgs = check_subdomain_abuse(parsed)
    if hit:
        signals["typosquatting"] = True
        signal_details.extend(msgs)

    # 2b — Suspicious TLD
    suffix = f".{ext.suffix}" if ext.suffix else ""
    if suffix.lower() in SUSPICIOUS_TLDS:
        signals["suspicious_tld"] = True
        signal_details.append(f"Suspicious TLD detected: {suffix}")

    # 2c — IP-based URL
    if is_ip_url(url):
        signals["ip_url"] = True
        signal_details.append("URL uses a raw IP address instead of a domain name")

    # 2d — Excessive subdomains
    subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []
    subdomain_parts = [p for p in subdomain_parts if p]
    if len(subdomain_parts) > 3:
        signals["excessive_subdomains"] = True
        signal_details.append(
            f"Excessive subdomains ({len(subdomain_parts)}) — may be obfuscation"
        )

    # 2e — URL length / obfuscation
    if len(url) > 120:
        signals["url_length_extreme"] = True
        signal_details.append(f"Extremely long URL ({len(url)} chars)")
    elif len(url) > 75:
        signals["url_length_long"] = True
        signal_details.append(f"Unusually long URL ({len(url)} chars)")

    if "@" in url:
        signals["at_symbol"] = True
        signal_details.append("URL contains @ symbol — possible redirect trick")

    # URL shortener
    for shortener in URL_SHORTENERS:
        if shortener in hostname:
            signals["url_shortener"] = True
            signal_details.append(f"URL uses shortener ({shortener})")
            break

    # Encoded characters
    if re.search(r'%[0-9A-Fa-f]{2}', url):
        decoded = unquote(url)
        if decoded != url:
            signals["encoded_chars"] = True
            signal_details.append("URL contains encoded/obfuscated characters")

    # 2f — HTTPS check
    if parsed.scheme == "http":
        signals["no_https"] = True
        signal_details.append("No HTTPS — connection is not encrypted")

    # 2g — Domain age
    if registered and not signals.get("url_shortener"):
        age = get_domain_age_days(registered)
        if age is not None:
            signals["domain_age_days"] = age
            if age < 30:
                signal_details.append(f"Very new domain (registered {age} days ago)")
            elif age < 90:
                signal_details.append(f"Recently registered domain ({age} days ago)")

    # 2h — Trusted domain check
    if registered:
        if registered.lower() in TRUSTED_DOMAINS:
            signals["trusted_domain"] = True
        else:
            signals["trusted_domain"] = False

    # 2i — Phishing keywords in URL path
    kw_count, kw_list = count_phishing_path_keywords(url)
    if kw_count >= 1:
        signals["phishing_path_keywords"] = kw_count
        signal_details.append(
            f"Phishing keywords in URL path: {', '.join(kw_list[:5])}"
        )

    return {"signals": signal_details, "flags": signals}


# ---------------------------------------------------------------------------
# LAYER 3 — Behavioral / NLP Signal Analysis
# ---------------------------------------------------------------------------
URGENCY_PATTERNS = [
    r'\bact now\b', r'\bimmediate(ly)?\b', r'\burgent(ly)?\b', r'\bexpires?\b',
    r'\bwithin \d+ hours?\b', r'\bwithin \d+ minutes?\b', r'\bdeadline\b',
    r'\blast chance\b', r'\btime.?sensitive\b', r'\bverify now\b',
    r'\brespond immediately\b', r'\baction required\b', r'\blimited time\b',
    r'\bdo (it|this) (now|today|immediately)\b', r'\bhurry\b',
    r'\bbefore (it\'?s? )?too late\b', r'\bdon\'?t (wait|delay|ignore)\b',
    r'\bfinal (notice|warning|reminder)\b', r'\btoday only\b',
    r'\b(only|just) \d+ (hours?|minutes?|days?) (left|remaining)\b',
    r'\bexpir(e|es|ed|ing) (soon|today|tomorrow)\b',
    r'\brequires? (your )?(immediate|urgent)\b',
    r'\bfailure to (respond|act|verify|comply)\b',
    r'\bwithout delay\b', r'\bas soon as possible\b', r'\basap\b',
    r'\b(must|need to) (act|respond|verify|confirm|update)\b',
    r'\bexpir(e|es|ed|ing) (within|in) \d+\b',
    r'\btime is running out\b', r'\bdo not delay\b'
]

THREAT_PATTERNS = [
    r'\baccount.{0,20}(suspend|terminat|block|disabl|clos|restrict|lock|compromis|breach|hack)(?:ed|ing|ion|ment)?\b',
    r'\b(suspend|terminat|block|disabl|restrict|lock)(?:ed|ing|ion)?.{0,20}account\b',
    r'\b(legal action|lawsuit|prosecut|warrant|arrest)\b',
    r'\b(unusual|unauthorized|suspicious|fraudulent).{0,20}(activit|access|login|transaction|charge|sign.?in)\b',
    r'\byour (account|access|service|subscription|membership).{0,20}(has been|will be|is being|was)\b',
    r'\bverify your identity\b',
    r'\bconfirm your (details|information|account|identity)\b',
    r'\b(permanent(ly)?|immediate(ly)?) (clos|delet|suspend|terminat|block|lock|restrict)\w*\b',
    r'\bif you (don\'?t|do not|fail to)\b',
    r'\bwe (detected|noticed|found|identified).{0,30}(unusual|suspicious|unauthorized|breach|fraud)\b',
    r'\b(breach|compromis|hack|unauthorized access).{0,20}(your|the|this)\b',
    r'\bsecurity (alert|warning|breach|incident|violation)\b',
    r'\b(risk|danger) of.{0,20}(los|clos|delet|suspend)\b',
    r'\byou (must|need to|have to|are required to) (verify|confirm|update|validate)\b',
    r'\byour.{0,20}(at risk|in danger|compromised|breached)\b',
    r'\b(restrict|limit|suspend|freeze).{0,15}(access|service|account)\b',
    r'\b(unusual|unrecognized) (device|location|ip|sign.?in|login)\b'
]

REWARD_PATTERNS = [
    r'\b(you (have |\'? ?ve )?(won|been selected|been chosen))\b',
    r'\b(congratulations?|congrats?).{0,30}(won|winner|prize|reward|gift|selected|chosen)\b',
    r'\b(free|complimentary).{0,20}(iphone|gift.?card|voucher|reward|prize|cash|money|laptop|ipad|android|samsung)\b',
    r'\bclaim your (prize|reward|gift|winning|bonus|cash)\b',
    r'\b\$\d+[\.,]?\d* (reward|bonus|credit|prize|cash|gift)\b',
    r'\blottery\b', r'\bsweepstakes\b', r'\bjackpot\b',
    r'\b(lucky|chosen|selected) (winner|person|user|customer|visitor)\b',
    r'\bexclusive (offer|deal|reward|bonus|gift)\b',
    r'\b(win|earn|get|receive) (up to )?\$\d+\b',
    r'\b(cash|money|funds?) (prize|reward|bonus|waiting)\b',
    r'\bno (cost|charge|fee|purchase)\b',
    r'\b(100|completely|totally|absolutely) free\b',
    r'\bgift.?card\b', r'\bvoucher\b', r'\bcoupon\b',
    r'\byou.{0,10}(eligible|qualify|qualified)\b',
    r'\b(million|thousand) (dollar|pound|euro)\b'
]

CREDENTIAL_PATTERNS = [
    r'\b(enter|provide|submit|update|confirm|input|type|send).{0,30}(password|credential|login|username|ssn|social security|pin|passcode)\b',
    r'\b(click|tap|press|follow).{0,20}(here|link|below|button).{0,30}(to|and) (verify|confirm|update|login|sign|restore|unlock|secure)\b',
    r'\bsign.?in (to|with|at) your\b',
    r'\byour (password|pin|otp|code).{0,20}(expire|reset|verif|change|update)\b',
    r'\blog.?in (to |at |with )?your\b',
    r'\b(reset|change|update) (your )?(password|credentials|pin)\b',
    r'\benter.{0,15}(below|here|form)\b',
    r'\b(user.?name|email|phone).{0,15}(and|&).{0,15}password\b',
    r'\bsecure (your |the )?(account|login|access)\b',
    r'\b(confirm|verify) (your )?(account|identity|email|phone)\b',
    r'\bclick (the )?(link|button|here) (below|above|to)\b',
    r'\b(re.?enter|retype) (your )?(password|credentials)\b'
]

IMPERSONATION_PATTERNS = [
    r'\b(apple|google|microsoft|amazon|paypal|netflix|irs|fbi|interpol|dhl|fedex|ups|usps|chase|wells.?fargo|citibank|bank of america|venmo|zelle|coinbase|binance).{0,30}(support|team|security|service|alert|notification|department|center|helpdesk)\b',
    r'\bofficial (notice|message|alert|warning|communication|notification)\b',
    r'\b(we are|this is|from the).{0,20}(apple|google|microsoft|amazon|paypal|netflix|irs|fbi)\b',
    r'\bdear (valued |loyal )?(customer|user|member|client|account.?holder)\b',
    r'\b(customer|technical|account) (support|service|department|team)\b',
    r'\b(authorized|official|verified) (representative|agent|department|notice)\b',
    r'\bon behalf of\b',
    r'\b(help.?desk|service.?desk|it department|admin(istration)?)\b',
    r'\bno.?reply@\b'
]

SENSITIVE_PATTERNS = [
    r'\b(social security|ssn|national id|passport|date of birth|dob|driver.?s? licen[sc]e)\b',
    r'\b(credit card|debit card|card number|cvv|expir(y|ation) date|cvc|card.?holder)\b',
    r'\b(bank account|routing number|iban|swift|account number|sort code)\b',
    r'\b(otp|one.?time.?password|verification code|security code|auth(entication)? code)\b',
    r'\b(billing|payment) (info|information|details|address)\b',
    r'\b(mother.?s? maiden|security question|secret answer)\b',
    r'\btax.?(id|number|return|filing)\b',
    r'\b(personal|private|sensitive|confidential) (info|information|data|details)\b',
    r'\b(wire transfer|money transfer|western union|moneygram)\b'
]


def _count_matches(text: str, patterns: list[str]) -> tuple[int, list[str]]:
    count = 0
    matched_texts = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            count += 1
            matched_texts.append(m.group())
    return count, matched_texts


def run_behavioral_analysis(text: str):
    """Scan text for phishing behavioral signals. Returns score + detail."""
    text_lower = text.lower()
    results = {}
    total_score = 0
    categories_triggered = 0

    # Urgency (+12 per, max 30)
    c, m = _count_matches(text_lower, URGENCY_PATTERNS)
    score = min(c * 12, 30)
    total_score += score
    if c:
        categories_triggered += 1
        results["urgency"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Urgency language detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Threats (+18 per, max 40)
    c, m = _count_matches(text_lower, THREAT_PATTERNS)
    score = min(c * 18, 40)
    total_score += score
    if c:
        categories_triggered += 1
        results["threat_language"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Threatening language detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Reward bait (+18 per, max 40)
    c, m = _count_matches(text_lower, REWARD_PATTERNS)
    score = min(c * 18, 40)
    total_score += score
    if c:
        categories_triggered += 1
        results["reward_bait"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Prize / reward bait detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Credential harvesting (+15 per, max 35)
    c, m = _count_matches(text_lower, CREDENTIAL_PATTERNS)
    score = min(c * 15, 35)
    total_score += score
    if c:
        categories_triggered += 1
        results["credential_harvesting"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Credential harvesting language detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Impersonation (+12 per, max 30)
    c, m = _count_matches(text_lower, IMPERSONATION_PATTERNS)
    score = min(c * 12, 30)
    total_score += score
    if c:
        categories_triggered += 1
        results["impersonation"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Brand/authority impersonation detected ({c} signal{'s' if c > 1 else ''})"
        }

    # Sensitive info (+15 per, max 35)
    c, m = _count_matches(text_lower, SENSITIVE_PATTERNS)
    score = min(c * 15, 35)
    total_score += score
    if c:
        categories_triggered += 1
        results["sensitive_info_request"] = {
            "triggered": True,
            "score": score,
            "matches": m,
            "detail": f"Requests for sensitive personal data ({c} signal{'s' if c > 1 else ''})"
        }

    # Multi-signal escalation bonus
    if categories_triggered >= 5:
        total_score += 35
    elif categories_triggered >= 4:
        total_score += 25
    elif categories_triggered >= 3:
        total_score += 15
    elif categories_triggered >= 2:
        total_score += 8

    return total_score, results, categories_triggered


# ---------------------------------------------------------------------------
# LAYER 4 — Scoring & Classification
# ---------------------------------------------------------------------------
def calculate_risk_score(threat_intel_hit: bool, domain_flags: dict,
                         behavioral_score: int, behavioral_categories: int):
    score = 0

    # Layer 1 — threat intel hit is very strong evidence
    if threat_intel_hit:
        score += 70

    # Layer 2 — domain signals
    domain_score = 0
    if domain_flags.get("typosquatting"):
        domain_score += 35
    if domain_flags.get("suspicious_tld"):
        domain_score += 18
    if domain_flags.get("ip_url"):
        domain_score += 30
    if domain_flags.get("excessive_subdomains"):
        domain_score += 22
    age = domain_flags.get("domain_age_days")
    if age is not None:
        if age < 30:
            domain_score += 28
        elif age < 90:
            domain_score += 12
    if domain_flags.get("no_https"):
        domain_score += 12
    if domain_flags.get("url_shortener"):
        domain_score += 18
    if domain_flags.get("url_length_extreme"):
        domain_score += 12
    if domain_flags.get("url_length_long"):
        domain_score += 6
    if domain_flags.get("at_symbol"):
        domain_score += 22
    if domain_flags.get("encoded_chars"):
        domain_score += 8
    # Phishing keywords in path
    path_kw = domain_flags.get("phishing_path_keywords", 0)
    if isinstance(path_kw, int) and path_kw > 0:
        domain_score += min(path_kw * 8, 25)

    # Count how many domain flags triggered (excluding meta flags)
    domain_flag_count = sum(1 for k, v in domain_flags.items()
                           if v and k not in ("trusted_domain", "domain_age_days", "phishing_path_keywords"))
    # Multi-domain-signal bonus
    if domain_flag_count >= 4:
        domain_score += 20
    elif domain_flag_count >= 3:
        domain_score += 15
    elif domain_flag_count >= 2:
        domain_score += 8
    score += min(domain_score, 60)

    # Layer 3 — behavioral signals (raised cap)
    score += min(behavioral_score, 65)

    # Cross-layer amplification: when BOTH domain AND behavioral trigger significantly
    if domain_score >= 20 and behavioral_score >= 20:
        score += 15
    elif domain_score >= 10 and behavioral_score >= 10:
        score += 8

    score = min(score, 100)

    # Classification thresholds
    if score <= 20:
        rank, emoji = "Safe", "🛡️"
    elif score <= 40:
        rank, emoji = "Suspicious", "⚠️"
    else:
        rank, emoji = "Scam", "🚨"

    return score, rank, emoji


# ---------------------------------------------------------------------------
# LAYER 5 — OCR (Image text extraction)
# ---------------------------------------------------------------------------
def extract_text_from_image(base64_string: str) -> tuple[str, str | None]:
    """Returns (extracted_text, error_message). error_message is None on success."""
    if not OCR_AVAILABLE:
        return "", (
            "OCR is not available. Install Tesseract OCR and Python packages "
            "(Pillow, pytesseract) to analyze screenshots. "
            "Alternatively, copy the text from the image and paste it in the Text tab."
        )
    try:
        # Strip data-URI prefix if present
        if "," in base64_string:
            base64_string = base64_string.split(",", 1)[1]
        img_data = base64.b64decode(base64_string)
        img = Image.open(io.BytesIO(img_data))
        text = pytesseract.image_to_string(img)
        extracted = text.strip()
        if not extracted:
            return "", "Could not extract any text from this image. The image may be too blurry, contain no text, or use unsupported fonts. Try pasting the text directly in the Text tab."
        logger.info(f"  📷 OCR extracted {len(extracted)} chars from image")
        return extracted, None
    except Exception as exc:
        logger.error(f"  OCR error: {exc}")
        return "", f"OCR processing failed: {str(exc)}. Try pasting the text directly in the Text tab."


def extract_urls_from_text(text: str) -> list[str]:
    """Find URLs embedded in arbitrary text."""
    url_pattern = r'https?://[^\s<>"\')\]}\,]+'
    return re.findall(url_pattern, text)


# ---------------------------------------------------------------------------
# Main /analyze endpoint
# ---------------------------------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    start_time = time.time()

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON payload"}), 400

    input_type = data.get("type", "").strip().lower()
    content = data.get("content", "").strip()

    if not content:
        return jsonify({"error": "No content provided"}), 400

    logger.info(f"{'='*50}")
    logger.info(f"📨 New analysis request: type={input_type}, length={len(content)}")

    # ----- Determine text + URLs to analyse -----
    urls_to_check: list[str] = []
    analysis_text = ""

    if input_type == "url":
        url = content
        if not url.startswith("http"):
            url = "http://" + url
        urls_to_check.append(url)
        # Use full URL as analysis text (domain + path + query carry signals)
        try:
            parsed = urlparse(url)
            analysis_text = unquote(
                (parsed.hostname or "") + (parsed.path or "") +
                ("?" + parsed.query if parsed.query else "")
            )
        except Exception:
            analysis_text = url
        logger.info(f"  🔗 URL to check: {url}")

    elif input_type == "text":
        analysis_text = content
        urls_to_check = extract_urls_from_text(content)
        logger.info(f"  📝 Text preview: {content[:80]}...")
        if urls_to_check:
            logger.info(f"  🔗 Found {len(urls_to_check)} embedded URLs")

    elif input_type == "image_base64":
        extracted, error = extract_text_from_image(content)
        if error:
            logger.warning(f"  ❌ Image analysis failed: {error}")
            return jsonify({"error": error}), 400
        analysis_text = extracted
        urls_to_check = extract_urls_from_text(extracted)
        logger.info(f"  📷 OCR text preview: {extracted[:80]}...")

    else:
        return jsonify({"error": f"Unknown input type: '{input_type}'"}), 400

    # ----- Run Layers -----

    # Layer 1 — Threat Intel (on each URL)
    threat_intel_result = {
        "triggered": False,
        "source": None,
        "detail": "No URLs to check" if not urls_to_check else "Not found in any threat intelligence feed",
        "sources_checked": []
    }
    for url in urls_to_check:
        result = run_threat_intel(url)
        if result["triggered"]:
            threat_intel_result = result
            break
        threat_intel_result["sources_checked"] = result["sources_checked"]

    # Layer 2 — Domain Analysis (on each URL)
    domain_result = {"signals": [], "flags": {}}
    for url in urls_to_check:
        dr = run_domain_analysis(url)
        domain_result["signals"].extend(dr["signals"])
        # Merge flags (keep worst-case)
        for k, v in dr["flags"].items():
            if k == "domain_age_days":
                existing = domain_result["flags"].get(k)
                if existing is None or v < existing:
                    domain_result["flags"][k] = v
            elif k == "trusted_domain":
                domain_result["flags"][k] = domain_result["flags"].get(k, True) and v
            elif k == "phishing_path_keywords":
                existing = domain_result["flags"].get(k, 0)
                domain_result["flags"][k] = max(existing, v) if isinstance(existing, int) else v
            else:
                domain_result["flags"][k] = domain_result["flags"].get(k, False) or v

    # Layer 3 — Behavioral
    behavioral_score, behavioral_results, behavioral_cats = run_behavioral_analysis(analysis_text)

    # Layer 4 — Score & classify
    risk_score, rank, emoji = calculate_risk_score(
        threat_intel_result["triggered"],
        domain_result["flags"],
        behavioral_score,
        behavioral_cats
    )

    # Trusted domain bypass
    if (domain_result["flags"].get("trusted_domain")
            and not threat_intel_result["triggered"]
            and behavioral_score < 10):
        risk_score = 0
        rank = "Safe"
        emoji = "🛡️"

    # Build layer breakdown for the frontend
    layers = {
        "threat_intel": {
            "triggered": threat_intel_result["triggered"],
            "source": threat_intel_result.get("source"),
            "detail": threat_intel_result.get("detail", ""),
            "sources_checked": threat_intel_result.get("sources_checked", [])
        },
        "domain_analysis": {
            "triggered": bool(domain_result["signals"]),
            "signals": domain_result["signals"]
        },
        "behavioral": {
            "triggered": behavioral_score > 0,
            "score": behavioral_score,
            "categories": behavioral_results,
            "signals": []
        },
        "classification": rank
    }
    # Flatten behavioral signals for display
    for cat, info in behavioral_results.items():
        layers["behavioral"]["signals"].append(info.get("detail", cat))

    elapsed = round((time.time() - start_time) * 1000)

    # Console logging summary
    rank_colors = {"Safe": "\033[32m", "Suspicious": "\033[33m", "Scam": "\033[31m"}
    rc = rank_colors.get(rank, "")
    logger.info(f"  📊 Result: {rc}{rank}\033[0m | Score: {risk_score}/100 | Time: {elapsed}ms")
    if behavioral_results:
        cats = ", ".join(behavioral_results.keys())
        logger.info(f"  🧠 Behavioral categories: {cats}")
    if domain_result["signals"]:
        logger.info(f"  🌐 Domain signals: {len(domain_result['signals'])} found")

    return jsonify({
        "risk_score": risk_score,
        "rank": rank,
        "emoji": emoji,
        "layers": layers
    })


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "ocr_available": OCR_AVAILABLE,
        "whois_available": WHOIS_AVAILABLE
    })


# ---------------------------------------------------------------------------
# Start background threads & run
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("🛡️  PhishGuard AI starting...")
    logger.info(f"  OCR available: {OCR_AVAILABLE}")
    logger.info(f"  WHOIS available: {WHOIS_AVAILABLE}")
    # Start OpenPhish feed loader in background
    t = threading.Thread(target=_load_openphish, daemon=True)
    t.start()
    app.run(debug=True, host="0.0.0.0", port=5000)
