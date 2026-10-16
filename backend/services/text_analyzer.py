import re
import html
from typing import List, Dict, Any, Tuple

# Compiled regex patterns for social engineering indicators
URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|hxxps?://|www\d{0,3}\.)[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/)))',
    re.IGNORECASE
)

URGENT_PATTERNS = [
    (r'\b(urgent|urgently|immediate|immediately|critical|action required|suspended|suspension|locked|within 24 hours|within 2 hours|account disabled|final notice|unauthorized access|security alert|fraud alert)\b', 'Urgency & Coercion', 'Pressures victim to react impulsively without verifying facts.'),
    (r'\b(act now|last chance|expire in|expires today|limited time|time sensitive|deadline)\b', 'Time-Pressure Trap', 'Artificial scarcity tactic to bypass critical thinking.')
]

CREDENTIAL_PATTERNS = [
    (r'\b(password|passcode|pin|ssn|social security|verify your account|confirm your identity|update billing|routing number|card number|cvv|security code|otp|one-time code)\b', 'Credential or Sensitive Data Solicitation', 'Direct request for high-value authentication credentials or private identifiers.'),
    (r'\b(login to|sign in at|re-enter|reset your credentials)\b', 'Authentication Harvesting Indicator', 'Attempts to redirect recipient to input confidential account credentials.')
]

FINANCIAL_PATTERNS = [
    (r'\b(wire transfer|bank transfer|escrow|western union|moneygram|cryptocurrency|bitcoin|btc|gift card|itunes card|amazon card|refund claim|tax rebate|unpaid invoice)\b', 'Unusual Payment / Financial Transfer Demand', 'Requests irreversible, untraceable, or unconventional funds movement.'),
    (r'\b(overdue payment|penalty fee|customs duty|redelivery fee|processing fee)\b', 'Unexpected Fee Demand', 'Demands an unexpected fee under the guise of delivery or account penalty.')
]

PRIZE_PATTERNS = [
    (r'\b(congratulations|congrats|you have won|winner|selected to win|lottery|lucky draw|free prize|reward of \$|claim your \$|cash reward)\b', 'Unsolicited Prize / Reward Lure', 'Entices victims with fake lottery prizes, free money, or unexpected awards.')
]

IMPERSONATED_BRANDS = [
    'chase', 'wells fargo', 'bank of america', 'citibank', 'paypal', 'apple',
    'microsoft', 'amazon', 'netflix', 'google', 'usps', 'fedex', 'ups', 'dhl',
    'irs', 'internal revenue', 'social security administration', 'geek squad',
    'meta', 'facebook', 'instagram', 'whatsapp', 'binance', 'coinbase'
]

def extract_urls(text: str) -> List[str]:
    """Safely extract all URLs from text."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    urls = []
    for m in matches:
        url = m[0] if isinstance(m, tuple) else m
        # Normalize defanged URLs
        url = url.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
        urls.append(url)
    return list(dict.fromkeys(urls))  # deduplicate preserving order

def normalize_text(text: str) -> str:
    """Normalize input text, decode entities, and strip control characters."""
    if not text:
        return ""
    # Unescape HTML entities
    cleaned = html.unescape(text)
    # Strip null bytes and non-printable control characters
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', cleaned)
    return cleaned.strip()

def analyze_text_indicators(text: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Examines text for known psychological triggers, social engineering patterns,
    brand mentions, and URL risks.
    """
    normalized = normalize_text(text)
    indicators = []
    flags = {
        'urgency_count': 0,
        'credential_count': 0,
        'financial_count': 0,
        'prize_count': 0,
        'brand_impersonation': [],
        'extracted_urls': extract_urls(normalized),
        'char_length': len(normalized),
        'word_count': len(normalized.split())
    }

    if not normalized or len(normalized) < 8:
        return indicators, flags

    lower_text = normalized.lower()

    # Check Urgency
    for pattern, title, desc in URGENT_PATTERNS:
        matches = re.findall(pattern, lower_text)
        if matches:
            flags['urgency_count'] += len(matches)
            indicators.append({
                'title': title,
                'severity': 'high',
                'description': f"{desc} Matched terms: {', '.join(set(matches[:3]))}."
            })

    # Check Credential requests
    for pattern, title, desc in CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, lower_text)
        if matches:
            flags['credential_count'] += len(matches)
            indicators.append({
                'title': title,
                'severity': 'high',
                'description': f"{desc} Matched terms: {', '.join(set(matches[:3]))}."
            })

    # Check Financial / Wire requests
    for pattern, title, desc in FINANCIAL_PATTERNS:
        matches = re.findall(pattern, lower_text)
        if matches:
            flags['financial_count'] += len(matches)
            indicators.append({
                'title': title,
                'severity': 'high' if 'wire' in lower_text or 'gift card' in lower_text else 'medium',
                'description': f"{desc} Matched terms: {', '.join(set(matches[:3]))}."
            })

    # Check Prize / Lottery
    for pattern, title, desc in PRIZE_PATTERNS:
        matches = re.findall(pattern, lower_text)
        if matches:
            flags['prize_count'] += len(matches)
            indicators.append({
                'title': title,
                'severity': 'high',
                'description': f"{desc} Matched terms: {', '.join(set(matches[:3]))}."
            })

    # Check Brand Impersonation
    detected_brands = [b for b in IMPERSONATED_BRANDS if re.search(r'\b' + re.escape(b) + r'\b', lower_text)]
    if detected_brands:
        flags['brand_impersonation'] = detected_brands
        # If brand mentioned alongside urgent/credential/link cues
        if flags['urgency_count'] > 0 or flags['credential_count'] > 0 or flags['extracted_urls']:
            indicators.append({
                'title': 'High-Profile Brand Mention with Threat Indicators',
                'severity': 'high',
                'description': f"Message references trusted institution(s) ({', '.join(detected_brands).title()}) in combination with urgent calls to action or suspicious links."
            })

    # Extracted URLs evaluation
    if flags['extracted_urls']:
        indicators.append({
            'title': f"Embedded Link(s) Detected ({len(flags['extracted_urls'])})",
            'severity': 'medium' if len(flags['extracted_urls']) == 1 else 'high',
            'description': f"Message contains outbound hyperlinks. Threat actors frequently embed shortlinks or spoofed domains to redirect victims to malicious login portals."
        })

    return indicators, flags
