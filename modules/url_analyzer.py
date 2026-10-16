
"""
modules/url_analyzer.py
------------------------
STEP 1 of the build order.

Analyzes a URL's structure for phishing / scam indicators.
Uses tldextract in OFFLINE mode (bundled suffix list only) so it
never needs internet access during a demo.

Used by: app.py, qr_scanner.py (when a QR code contains a link)
"""

import re

try:
    import tldextract
    # IMPORTANT: suffix_list_urls=() forces tldextract to use its
    # bundled snapshot instead of downloading from the internet.
    # Without this, the app can hang or error out with no wifi.
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "webscr", "ebayisapi", "password", "billing",
    "reset", "unlock", "suspend",
]

SUSPICIOUS_TLDS = [
    "xyz", "top", "info", "click", "link", "work", "gq", "tk", "ml", "cf", "ga", "loan", "win",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at",
]

KNOWN_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "sbi", "hdfc", "icici",
    "paytm", "flipkart", "irctc", "aadhaar",
]

IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}")


def _extract_domain_parts(url):
    """Return (subdomain, domain, suffix)."""
    if TLDEXTRACT_AVAILABLE:
        ext = _TLD_EXTRACTOR(url)
        return ext.subdomain, ext.domain, ext.suffix
    # Fallback if tldextract isn't installed at all
    match = re.search(r"https?://([^/]+)", url if "://" in url else "http://" + url)
    host = match.group(1) if match else url
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:-2]) if len(parts) > 2 else "", parts[-2], parts[-1]
    return "", host, ""


def is_url_like(text):
    """Quick check: does this string look like a URL/link at all?"""
    if not text:
        return False
    text = text.strip().lower()
    return bool(
        text.startswith("http://") or text.startswith("https://") or
        text.startswith("www.") or re.search(r"\.[a-z]{2,}(/|$)", text)
    )


def analyze_url(raw_url):
    """
    Analyze a URL and return a dictionary of detected indicators.
    Never raises - malformed/empty input is handled gracefully.
    """
    result = {
        "valid": True,
        "has_https": False,
        "is_ip_address": False,
        "has_at_symbol": False,
        "excessive_subdomains": False,
        "suspicious_tld": False,
        "is_shortener": False,
        "suspicious_keywords_found": [],
        "brand_impersonation": None,
        "domain_length_long": False,
        "suspicious_characters": False,
        "indicators": [],
        "empty_input": False,
        "domain": "",
    }

    if not raw_url or not raw_url.strip():
        result["valid"] = False
        result["empty_input"] = True
        return result

    url = raw_url.strip()
    url_lower = url.lower()

    try:
        result["has_https"] = url_lower.startswith("https://")
        if not url_lower.startswith(("http://", "https://")):
            result["indicators"].append("URL missing http(s):// scheme (treated as suspicious)")

        host_check = url_lower.replace("https://", "").replace("http://", "").split("/")[0]
        if IP_PATTERN.match(host_check):
            result["is_ip_address"] = True
            result["indicators"].append("Uses an IP address instead of a domain name")

        if "@" in url:
            result["has_at_symbol"] = True
            result["indicators"].append("Contains '@' symbol (can hide the real destination)")

        if re.search(r"[^\x00-\x7F]", url) or url.count("-") > 3:
            result["suspicious_characters"] = True
            result["indicators"].append("Contains unusual or excessive characters")

        subdomain, domain, suffix = _extract_domain_parts(url)
        result["domain"] = f"{domain}.{suffix}" if suffix else domain

        if subdomain and len(subdomain.split(".")) >= 3:
            result["excessive_subdomains"] = True
            result["indicators"].append("Excessive number of subdomains")

        if suffix and suffix.lower() in SUSPICIOUS_TLDS:
            result["suspicious_tld"] = True
            result["indicators"].append(f"Uses an uncommon/high-risk domain extension (.{suffix})")

        for shortener in URL_SHORTENERS:
            if shortener in url_lower:
                result["is_shortener"] = True
                result["indicators"].append(f"Uses a URL shortener ({shortener}) which hides the real destination")
                break

        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        if found_keywords:
            result["suspicious_keywords_found"] = found_keywords
            result["indicators"].append(f"Suspicious keywords in URL ({', '.join(found_keywords[:3])})")

        if len(host_check) > 40:
            result["domain_length_long"] = True
            result["indicators"].append("Unusually long domain/host name")

        for brand in KNOWN_BRANDS:
            if brand in url_lower and brand != domain.lower():
                result["brand_impersonation"] = brand
                result["indicators"].append(f"Possible impersonation of brand '{brand}' (not the real domain)")
                break

    except Exception as e:
        result["valid"] = False
        result["indicators"].append(f"Could not fully parse URL ({e}) - treating as suspicious")

    return result


