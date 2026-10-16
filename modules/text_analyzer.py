"""
modules/text_analyzer.py
--------------------------
STEP 3 of the build order.

Detects scam/phishing indicators in free text (SMS/email/WhatsApp/
QR-code payloads). Does NOT compute a score itself - that's
risk_engine.py's job. This module only detects and classifies.

Used by: app.py, qr_scanner.py (when a QR code contains plain text)
"""

import re

URGENCY_WORDS = [
    "immediately", "urgent", "right away", "act now", "within 24 hours",
    "within 30 minutes", "expire", "expires", "expiring", "last chance",
    "final notice", "asap", "hurry", "time-sensitive", "before it's too late",
]

THREAT_WORDS = [
    "account will be blocked", "account suspended", "account suspension",
    "legal action", "penalty", "arrest", "fine", "deactivated",
    "account will be closed", "your account has been locked", "blocked within",
]

FINANCIAL_REQUEST_WORDS = [
    "transfer money", "send money", "pay now", "processing fee",
    "registration fee", "deposit", "wire transfer", "bank details",
    "pay ₹", "pay rs", "pay $", "advance payment", "gift card",
    "claim your prize", "claim your reward",
]

OTP_PASSWORD_WORDS = [
    "otp", "one time password", "pin number", "password", "cvv",
    "share your otp", "verification code", "security code",
]

PRIZE_LOTTERY_WORDS = [
    "congratulations", "you have won", "you've won", "winner",
    "lottery", "lucky draw", "prize", "jackpot", "claim your prize",
]

JOB_SCAM_WORDS = [
    "work from home", "work-from-home", "selected for a job",
    "registration fee", "job offer", "hiring immediately",
    "earn from home", "part time job", "no experience required",
]

KYC_ACCOUNT_WORDS = [
    "kyc", "verify your account", "update your account", "verify your details",
    "re-verify", "confirm your identity", "account verification",
]

IMPERSONATION_WORDS = [
    "bank", "income tax", "customs", "government", "rbi", "sbi", "hdfc",
    "icici", "paytm", "amazon", "flipkart", "courier", "fedex", "police",
    "electricity board", "aadhaar", "pan card",
]

SENSITIVE_INFO_WORDS = [
    "share your", "provide your", "enter your", "confirm your card number",
    "bank account number", "aadhaar number", "pan number",
]

URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+|\b\S+\.(?:com|net|org|xyz|info|biz|top|link|click)\S*)", re.IGNORECASE)


def _count_matches(text_lower, word_list):
    return [w for w in word_list if w in text_lower]


def analyze_text(text):
    """
    Analyze a message and return a dictionary of detected indicators.
    """
    if not text or not text.strip():
        return {
            "urgency": False, "threat": False, "financial_request": False,
            "otp_password": False, "prize_lottery": False, "job_scam": False,
            "kyc_account": False, "impersonation": False, "sensitive_info": False,
            "urls_found": [], "indicators": [], "empty_input": True,
        }

    text_lower = text.lower()

    urgency_matches = _count_matches(text_lower, URGENCY_WORDS)
    threat_matches = _count_matches(text_lower, THREAT_WORDS)
    financial_matches = _count_matches(text_lower, FINANCIAL_REQUEST_WORDS)
    otp_matches = _count_matches(text_lower, OTP_PASSWORD_WORDS)
    prize_matches = _count_matches(text_lower, PRIZE_LOTTERY_WORDS)
    job_matches = _count_matches(text_lower, JOB_SCAM_WORDS)
    kyc_matches = _count_matches(text_lower, KYC_ACCOUNT_WORDS)
    impersonation_matches = _count_matches(text_lower, IMPERSONATION_WORDS)
    sensitive_matches = _count_matches(text_lower, SENSITIVE_INFO_WORDS)

    urls_found = URL_PATTERN.findall(text)

    indicators = []
    if urgency_matches:
        indicators.append(f"Urgency language detected ({', '.join(urgency_matches[:3])})")
    if threat_matches:
        indicators.append(f"Account threat detected ({', '.join(threat_matches[:2])})")
    if financial_matches:
        indicators.append(f"Financial request detected ({', '.join(financial_matches[:2])})")
    if otp_matches:
        indicators.append(f"OTP/password request detected ({', '.join(otp_matches[:2])})")
    if prize_matches:
        indicators.append(f"Prize/lottery language detected ({', '.join(prize_matches[:2])})")
    if job_matches:
        indicators.append(f"Fake job offer language detected ({', '.join(job_matches[:2])})")
    if kyc_matches:
        indicators.append(f"KYC/account verification request detected ({', '.join(kyc_matches[:2])})")
    if impersonation_matches:
        indicators.append(f"Possible impersonation of organization ({', '.join(impersonation_matches[:2])})")
    if sensitive_matches:
        indicators.append("Request for sensitive personal information detected")
    if urls_found:
        indicators.append(f"Contains {len(urls_found)} link(s) - will be analyzed separately")

    return {
        "urgency": bool(urgency_matches),
        "threat": bool(threat_matches),
        "financial_request": bool(financial_matches),
        "otp_password": bool(otp_matches),
        "prize_lottery": bool(prize_matches),
        "job_scam": bool(job_matches),
        "kyc_account": bool(kyc_matches),
        "impersonation": bool(impersonation_matches),
        "sensitive_info": bool(sensitive_matches),
        "urls_found": urls_found,
        "indicators": indicators,
        "empty_input": False,
    }


def classify_text(indicators):
    """Rule-based threat category label, ordered by specificity."""
    if indicators.get("empty_input"):
        return "Unknown/Suspicious"

    if indicators["job_scam"]:
        return "Job Scam"
    if indicators["prize_lottery"]:
        return "Lottery/Prize Scam"
    if indicators["kyc_account"] or (indicators["threat"] and indicators["impersonation"]):
        return "Account/KYC Scam"
    if indicators["otp_password"] or indicators["urls_found"]:
        return "Phishing"
    if indicators["financial_request"]:
        return "Financial Scam"

    any_flag = any([
        indicators["urgency"], indicators["threat"], indicators["financial_request"],
        indicators["otp_password"], indicators["prize_lottery"], indicators["job_scam"],
        indicators["kyc_account"], indicators["impersonation"], indicators["sensitive_info"],
    ])
    return "Unknown/Suspicious" if any_flag else "Safe"

