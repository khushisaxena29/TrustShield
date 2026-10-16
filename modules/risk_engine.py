"""
modules/risk_engine.py
------------------------
STEP 2 of the build order.

Turns indicator dictionaries (from text_analyzer.py / url_analyzer.py)
into a transparent 0-100 risk score with a full point-by-point
breakdown. Also holds risk-level thresholds and safety recommendations.

Used by: app.py
"""

TEXT_WEIGHTS = {
    "Urgency detected": 15,
    "Financial request detected": 20,
    "OTP/password request detected": 20,
    "Account threat detected": 15,
    "Impersonation detected": 15,
    "Prize/lottery language detected": 15,
    "Job scam language detected": 15,
    "KYC/account verification request detected": 15,
    "Sensitive information request detected": 15,
}

URL_WEIGHTS = {
    "Suspicious URL structure": 25,
    "Shortened URL": 10,
    "IP address used instead of domain": 20,
    "'@' symbol trick": 15,
    "Excessive subdomains": 10,
    "Suspicious domain extension": 10,
    "Suspicious keywords in URL": 10,
    "Brand impersonation": 20,
    "Missing HTTPS": 10,
    "Long/unusual domain": 5,
}


def score_text(indicators):
    """Convert text/message indicators into a risk breakdown."""
    breakdown = []
    if indicators.get("empty_input"):
        return 0, breakdown

    if indicators["urgency"]:
        breakdown.append(("Urgency detected", TEXT_WEIGHTS["Urgency detected"]))
    if indicators["financial_request"]:
        breakdown.append(("Financial request detected", TEXT_WEIGHTS["Financial request detected"]))
    if indicators["otp_password"]:
        breakdown.append(("OTP/password request detected", TEXT_WEIGHTS["OTP/password request detected"]))
    if indicators["threat"]:
        breakdown.append(("Account threat detected", TEXT_WEIGHTS["Account threat detected"]))
    if indicators["impersonation"]:
        breakdown.append(("Impersonation detected", TEXT_WEIGHTS["Impersonation detected"]))
    if indicators["prize_lottery"]:
        breakdown.append(("Prize/lottery language detected", TEXT_WEIGHTS["Prize/lottery language detected"]))
    if indicators["job_scam"]:
        breakdown.append(("Job scam language detected", TEXT_WEIGHTS["Job scam language detected"]))
    if indicators["kyc_account"]:
        breakdown.append(("KYC/account verification request detected", TEXT_WEIGHTS["KYC/account verification request detected"]))
    if indicators["sensitive_info"]:
        breakdown.append(("Sensitive information request detected", TEXT_WEIGHTS["Sensitive information request detected"]))

    total = min(sum(points for _, points in breakdown), 100)
    return total, breakdown


def score_url(indicators):
    """Convert URL indicators into a risk breakdown."""
    breakdown = []

    if indicators.get("empty_input"):
        return 0, breakdown
    if not indicators.get("valid", True):
        breakdown.append(("Suspicious URL structure", URL_WEIGHTS["Suspicious URL structure"]))
        return min(sum(p for _, p in breakdown), 100), breakdown

    if not indicators["has_https"]:
        breakdown.append(("Missing HTTPS", URL_WEIGHTS["Missing HTTPS"]))
    if indicators["is_shortener"]:
        breakdown.append(("Shortened URL", URL_WEIGHTS["Shortened URL"]))
    if indicators["is_ip_address"]:
        breakdown.append(("IP address used instead of domain", URL_WEIGHTS["IP address used instead of domain"]))
    if indicators["has_at_symbol"]:
        breakdown.append(("'@' symbol trick", URL_WEIGHTS["'@' symbol trick"]))
    if indicators["excessive_subdomains"]:
        breakdown.append(("Excessive subdomains", URL_WEIGHTS["Excessive subdomains"]))
    if indicators["suspicious_tld"]:
        breakdown.append(("Suspicious domain extension", URL_WEIGHTS["Suspicious domain extension"]))
    if indicators["suspicious_keywords_found"]:
        breakdown.append(("Suspicious keywords in URL", URL_WEIGHTS["Suspicious keywords in URL"]))
    if indicators["brand_impersonation"]:
        breakdown.append(("Brand impersonation", URL_WEIGHTS["Brand impersonation"]))
    if indicators["domain_length_long"]:
        breakdown.append(("Long/unusual domain", URL_WEIGHTS["Long/unusual domain"]))

    total = min(sum(points for _, points in breakdown), 100)
    return total, breakdown


def combine_scores(text_score, url_score):
    """Combine a text score and a url score (e.g. message containing a link)."""
    if text_score == 0:
        return min(url_score, 100)
    if url_score == 0:
        return min(text_score, 100)
    combined = max(text_score, url_score) + (min(text_score, url_score) * 0.3)
    return min(round(combined), 100)


def get_risk_level(score):
    if score <= 30:
        return "SAFE"
    elif score <= 40:
        return "MEDIUM"
    elif score <= 50:
        return "HIGH"
    else:
        return "CRITICAL"


def get_risk_color(level):
    return {
        "SAFE": "#2ecc71",
        "MEDIUM": "#f1c40f",
        "HIGH": "#e67e22",
        "CRITICAL": "#e74c3c",
    }.get(level, "#95a5a6")


def get_recommendations(threat_category):
    """Return (what_not_to_do, what_to_do) lists tailored to the threat category."""
    what_not_to_do = [
        "Do not click suspicious links",
        "Do not share your OTP with anyone",
        "Do not share passwords or PINs",
        "Do not transfer money based on this message alone",
    ]
    what_to_do = [
        "Verify through the organization's official website or app",
        "Contact the organization using an official, published number",
        "Block and report the sender",
    ]

    if threat_category == "Financial Scam":
        what_to_do.append("Contact your bank immediately if you already shared details")
    elif threat_category == "Account/KYC Scam":
        what_to_do.append("Log in only via the official app, never through a link in the message")
    elif threat_category == "Job Scam":
        what_not_to_do.append("Do not pay any 'registration' or 'processing' fee for a job")
        what_to_do.append("Research the company independently before proceeding")
    elif threat_category == "Lottery/Prize Scam":
        what_not_to_do.append("Do not provide bank details to 'claim' a prize you never entered for")
    elif threat_category == "Phishing":
        what_to_do.append("Hover over links to check the real destination before clicking")

    return what_not_to_do, what_to_do


