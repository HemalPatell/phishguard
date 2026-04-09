"""
feature_extractor.py
--------------------
Extracts numeric features from a raw URL string.
Must stay in sync with ml/train_model.py so that
inference features match training features exactly.
"""

import re
from urllib.parse import urlparse

# Keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "bank", "paypal", "ebay", "amazon", "apple", "microsoft",
    "confirm", "password", "credential", "free", "winner", "prize",
    "click", "here", "urgent", "suspend", "alert", "limited",
]

FEATURE_NAMES = [
    "url_length", "hostname_length", "ip_in_url", "uses_https",
    "dot_count", "hyphen_count", "at_symbol_count", "subdomain_count",
    "suspicious_count", "path_depth", "has_query", "has_double_slash",
]


def _has_ip_address(url: str) -> int:
    """Returns 1 if the URL contains an IPv4 address."""
    return 1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", url) else 0


def _count_subdomains(url: str) -> int:
    """Counts the number of subdomains in the hostname."""
    try:
        host = urlparse(url).netloc.split(":")[0]
        return max(0, len(host.split(".")) - 2)
    except Exception:
        return 0


def _count_suspicious_keywords(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def extract_features(url: str) -> list:
    """
    Return a list of numeric features (same order as FEATURE_NAMES).
    """
    parsed = urlparse(url)

    return [
        len(url),                               # 1. url_length
        len(parsed.netloc),                     # 2. hostname_length
        _has_ip_address(url),                   # 3. ip_in_url
        1 if parsed.scheme == "https" else 0,   # 4. uses_https
        url.count("."),                         # 5. dot_count
        url.count("-"),                         # 6. hyphen_count
        url.count("@"),                         # 7. at_symbol_count
        _count_subdomains(url),                 # 8. subdomain_count
        _count_suspicious_keywords(url),        # 9. suspicious_count
        parsed.path.count("/"),                 # 10. path_depth
        1 if parsed.query else 0,               # 11. has_query
        1 if "//" in parsed.path else 0,        # 12. has_double_slash
    ]


def get_feature_dict(url: str) -> dict:
    """Returns a dictionary mapping feature names → values (for display)."""
    return dict(zip(FEATURE_NAMES, extract_features(url)))
