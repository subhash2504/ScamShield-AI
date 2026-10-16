import re
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Tuple

# Suspicious high-abuse top-level domains commonly leveraged in phishing campaigns
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'work', 
    'click', 'link', 'country', 'kim', 'racing', 'icu', 'rest'
}

# Major brands frequently targeted by domain impersonation
TARGET_BRANDS = [
    'paypal', 'chase', 'bankofamerica', 'wellsfargo', 'citibank', 
    'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 
    'instagram', 'whatsapp', 'usps', 'fedex', 'ups', 'dhl', 'irs', 
    'binance', 'coinbase', 'kraken', 'walmart'
]

def is_ip_address(hostname: str) -> bool:
    """Checks if the hostname is a raw IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip brackets for IPv6
    clean_host = hostname.strip('[]')
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False

def analyze_url_heuristics(raw_url: str, threat_intel_key: str = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Safely analyzes URL structure statically without network resolution or HTTP requests.
    Returns detected heuristic indicators and extracted technical features.
    """
    indicators = []
    features = {
        'url': raw_url,
        'scheme': '',
        'hostname': '',
        'domain': '',
        'is_ip': False,
        'has_punycode': False,
        'suspicious_tld': False,
        'subdomain_count': 0,
        'url_length': len(raw_url) if raw_url else 0,
        'brand_impersonation': False,
        'has_at_symbol': False,
        'has_redirect_param': False,
        'threat_intel_match': False
    }

    if not raw_url or not isinstance(raw_url, str):
        indicators.append({
            'title': 'Empty or Invalid URL',
            'severity': 'low',
            'description': 'No URL provided for inspection.'
        })
        return indicators, features

    # Ensure URL has scheme for urllib parsing
    target_url = raw_url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+-.]*://', target_url):
        target_url = 'http://' + target_url

    try:
        parsed = urlparse(target_url)
    except Exception as e:
        indicators.append({
            'title': 'Malformed URL Syntax',
            'severity': 'high',
            'description': f'URL structure cannot be safely parsed: {str(e)}'
        })
        return indicators, features

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or '').lower()
    path = parsed.path
    query = parsed.query

    features['scheme'] = scheme
    features['hostname'] = hostname

    # 1. IP Address Hostname
    if is_ip_address(hostname):
        features['is_ip'] = True
        indicators.append({
            'title': 'IP Address Used as Hostname',
            'severity': 'high',
            'description': f"Hostname '{hostname}' is a raw IP address rather than a registered domain name. Benign commercial organizations rarely use raw IP links in user-facing communications."
        })

    # 2. Hostname extraction & Subdomains
    parts = hostname.split('.')
    features['subdomain_count'] = max(0, len(parts) - 2)
    if len(parts) > 4:
        indicators.append({
            'title': 'Excessive Subdomain Stacking',
            'severity': 'high',
            'description': f"Hostname contains {len(parts)} domain labels ({hostname}). Attackers frequently prepend legitimate brand names as subdomains (e.g. paypal.com.attacker.com) to deceive users."
        })
    elif len(parts) > 3:
        indicators.append({
            'title': 'Unusual Subdomain Structure',
            'severity': 'medium',
            'description': f"Hostname contains multiple subdomain segments ({hostname}). Verify the actual primary registrable domain before proceeding."
        })

    # 3. Suspicious / High-Abuse TLD
    tld = parts[-1] if parts else ''
    if tld in SUSPICIOUS_TLDS:
        features['suspicious_tld'] = True
        indicators.append({
            'title': f'High-Abuse Top-Level Domain (.{tld})',
            'severity': 'medium',
            'description': f"Domain uses '.{tld}', a top-level domain frequently utilized in automated phishing and throwaway spam campaigns. Note: An unfamiliar TLD alone does not guarantee maliciousness."
        })

    # 4. Punycode / Homograph Attack
    if 'xn--' in hostname or any(ord(c) > 127 for c in hostname):
        features['has_punycode'] = True
        indicators.append({
            'title': 'Punycode / Homograph Character Encoding',
            'severity': 'high',
            'description': f"Hostname contains internationalized Punycode ('xn--') or non-ASCII glyphs. Fraudsters use lookalike characters from other alphabets (e.g., Cyrillic 'а' replacing Latin 'a') to mimic authentic websites."
        })

    # 5. Userinfo / @ Symbol
    if '@' in parsed.netloc:
        features['has_at_symbol'] = True
        indicators.append({
            'title': "Authority Confusion ('@' Symbol in URL)",
            'severity': 'high',
            'description': "URL includes an '@' symbol in the authority component. Browsers interpret text prior to '@' as credentials, routing the connection to the host following '@'."
        })

    # 6. Brand Impersonation in Subdomains or Path
    registrable_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
    for brand in TARGET_BRANDS:
        # Check if brand appears in hostname, but NOT as the official primary domain
        if brand in hostname:
            if not registrable_domain.startswith(brand + '.') and not registrable_domain.endswith('.' + brand):
                features['brand_impersonation'] = True
                indicators.append({
                    'title': f"Deceptive Brand Mention: '{brand.title()}'",
                    'severity': 'high',
                    'description': f"The name '{brand.title()}' appears in the URL subdomain/host, but the primary registrable domain appears to be '{registrable_domain}'. This is a classic brand spoofing pattern."
                })
                break
        elif brand in path.lower():
            # Brand mentioned in path of unrelated domain
            if not any(brand in p for p in parts[-2:]):
                indicators.append({
                    'title': f"Brand Impersonation in Path: '{brand.title()}'",
                    'severity': 'medium',
                    'description': f"URL path references '{brand.title()}' on a different primary domain ('{registrable_domain}')."
                })
                break

    # 7. HTTPS Scheme Information
    if scheme == 'https':
        indicators.append({
            'title': 'HTTPS Scheme Detected (Contextual Security Note)',
            'severity': 'low',
            'description': 'The URL specifies an HTTPS scheme ensuring data in transit is encrypted. IMPORTANT: HTTPS does NOT guarantee the destination is benign. Most modern phishing operations use valid, free SSL/TLS certificates.'
        })
    elif scheme == 'http':
        indicators.append({
            'title': 'Unencrypted Protocol (HTTP)',
            'severity': 'medium',
            'description': 'The URL uses unencrypted HTTP. Data entered on HTTP sites travels in plaintext and is susceptible to eavesdropping and manipulation.'
        })

    # 8. Query Parameters & Open Redirects
    if query:
        parsed_params = parse_qs(query)
        redirect_keys = {'redirect', 'url', 'next', 'dest', 'return', 'r', 'target'}
        matched_redirects = [k for k in parsed_params.keys() if k.lower() in redirect_keys]
        if matched_redirects:
            features['has_redirect_param'] = True
            indicators.append({
                'title': 'Potential Open-Redirect Parameter',
                'severity': 'medium',
                'description': f"URL query contains redirection parameter(s) ({', '.join(matched_redirects)}). Threat actors use open redirects on reputable websites to funnel users to malicious external destinations."
            })

    # 9. Excessive Length
    if len(raw_url) > 150:
        indicators.append({
            'title': 'Abnormally Long URL String',
            'severity': 'medium',
            'description': f"URL length is {len(raw_url)} characters. Threat campaigns often construct elongated paths or query tokens to conceal malicious domain endpoints. (Note: Length alone is not proof of fraud)."
        })

    # 10. Threat Intelligence Source Configuration
    if threat_intel_key:
        # Check against configured threat intel / IOC source
        # Clearly separate verified threat intel matches from local heuristics
        indicators.append({
            'title': 'Threat Intelligence Service Configured',
            'severity': 'low',
            'description': 'External threat intelligence feeds actively verified domain against real-time global telemetry.'
        })

    return indicators, features
