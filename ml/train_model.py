"""
train_model.py
--------------
Generates a synthetic phishing/legitimate URL dataset,
trains a Random Forest classifier, and saves the model
to ml/phishing_model.pkl using joblib.

Run this ONCE before starting Django:
    python ml/train_model.py
"""

import os
import sys
import re
import random
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

# ─────────────────────────────────────────────────────────────────────────────
# 1. FEATURE EXTRACTION (same logic used by Django at prediction time)
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "bank", "paypal", "ebay", "amazon", "apple", "microsoft",
    "confirm", "password", "credential", "free", "winner", "prize",
    "click", "here", "urgent", "suspend", "alert", "limited",
]

def has_ip_address(url: str) -> int:
    """Returns 1 if the host part looks like an IPv4 address."""
    pattern = r"(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(pattern, url) else 0


def count_subdomains(url: str) -> int:
    """Counts the number of subdomains (dots in hostname minus 1)."""
    try:
        host = urlparse(url).netloc
        host = host.split(":")[0]          # strip port if present
        parts = host.split(".")
        return max(0, len(parts) - 2)      # e.g. a.b.com → 1 subdomain
    except Exception:
        return 0


def count_suspicious_keywords(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def extract_features(url: str) -> list:
    """
    Extract a fixed-length numeric feature vector from a URL.
    Returns a list of 12 features.
    """
    parsed = urlparse(url)

    # 1. URL total length
    url_length = len(url)

    # 2. Hostname length
    hostname_length = len(parsed.netloc)

    # 3. Has IP address in host
    ip_in_url = has_ip_address(url)

    # 4. Uses HTTPS
    uses_https = 1 if parsed.scheme == "https" else 0

    # 5. Number of dots in URL
    dot_count = url.count(".")

    # 6. Number of hyphens (dashes)
    hyphen_count = url.count("-")

    # 7. Number of "@" symbols (phishing trick to mislead users)
    at_symbol_count = url.count("@")

    # 8. Number of subdomains
    subdomain_count = count_subdomains(url)

    # 9. Number of suspicious keywords
    suspicious_count = count_suspicious_keywords(url)

    # 10. Path depth (number of "/" in path)
    path_depth = parsed.path.count("/")

    # 11. Has query string (1/0)
    has_query = 1 if parsed.query else 0

    # 12. URL contains double-slash redirect (//)
    has_double_slash = 1 if "//" in parsed.path else 0

    return [
        url_length,
        hostname_length,
        ip_in_url,
        uses_https,
        dot_count,
        hyphen_count,
        at_symbol_count,
        subdomain_count,
        suspicious_count,
        path_depth,
        has_query,
        has_double_slash,
    ]


FEATURE_NAMES = [
    "url_length", "hostname_length", "ip_in_url", "uses_https",
    "dot_count", "hyphen_count", "at_symbol_count", "subdomain_count",
    "suspicious_count", "path_depth", "has_query", "has_double_slash",
]

# ─────────────────────────────────────────────────────────────────────────────
# 2. SYNTHETIC DATASET GENERATION
# ─────────────────────────────────────────────────────────────────────────────

LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
    "https://www.youtube.com",
    "https://www.reddit.com",
    "https://www.linkedin.com",
    "https://www.twitter.com",
    "https://www.facebook.com",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/iphone",
    "https://docs.python.org/3/library/re.html",
    "https://www.django-rest-framework.org",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://pandas.pydata.org/docs/user_guide/index.html",
    "https://numpy.org/doc/stable/reference/generated/numpy.array.html",
    "https://www.bbc.com/news",
    "https://www.nytimes.com",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.udemy.com/course/python-bootcamp",
    "https://portal.azure.com",
    "https://console.aws.amazon.com",
    "https://cloud.google.com/compute",
    "https://www.stripe.com/docs",
    "https://api.openai.com/v1/chat",
    "https://www.shopify.com/pricing",
    "https://www.dropbox.com/home",
    "https://drive.google.com/drive/my-drive",
    "https://mail.google.com/mail/u/0",
    "https://calendar.google.com",
    "https://www.notion.so/workspace",
    "https://trello.com/b/boardid/project",
    "https://slack.com/intl/en-in",
    "https://zoom.us/meeting",
    "https://www.paypal.com/myaccount/summary",
    "https://www.netflix.com/browse",
    "https://www.spotify.com/account",
    "https://www.twitch.tv/directory",
    "https://www.medium.com/tag/python",
    "https://www.forbes.com/technology",
    "https://www.techcrunch.com",
    "https://www.wired.com",
    "https://www.theverge.com",
    "https://www.cnn.com/world",
    "https://www.reuters.com",
    "https://www.bloomberg.com/markets",
    "https://finance.yahoo.com",
    "https://www.indeed.com/jobs",
    "https://www.glassdoor.com/Reviews",
]

PHISHING_URLS = [
    "http://192.168.1.1/login/verify",
    "http://paypa1-secure.verify-account.com/login",
    "http://www.google-login-secure.phish.net/signin",
    "http://amazon-update.account-verify.tk/confirm",
    "http://secure-bankofamerica.com/login",
    "http://apple-id-verify.site/account/update",
    "http://microsoft-alert-user.com/password-reset",
    "http://ebay-secure-account.com/verify/login",
    "http://paypal.login-secure-account.com",
    "http://free-prize-winner.click/claim-now",
    "http://172.16.254.1/banking/login?user=admin",
    "http://update-your-account.verify-now.net/user",
    "http://suspicious-login.bank-secure.co/verify",
    "http://credential-update.amazon-fake.com/signin",
    "http://limited-offer-winner.prize-free.biz/click",
    "http://secure-verify-account-urgent.com/login",
    "http://bankofamerica.account-suspended.net/alert",
    "http://wells-fargo-alert.com/account/verify",
    "http://chase-bank-update.secure.phish.info/login",
    "http://irs-tax-refund.gov-alert.com/claim",
    "http://covid-relief-payment.gov-free.com/apply",
    "http://netflix-suspend-alert.com/account/verify",
    "http://spotify-premium-free.click/get-now",
    "http://steam-free-games.phish.ru/claim",
    "http://apple-invoice-confirm.com/update-payment",
    "http://10.0.0.1/admin/login",
    "http://instagram-verify-account.net/login@user",
    "http://facebook-security-alert.login-verify.com",
    "http://whatsapp-free-gold.biz/install",
    "http://linkedin-verify-email.com/signin?urgent=1",
    "http://docusign-document-sign.phish.com/login",
    "http://dropbox-shared-file.secure-link.tk/view",
    "http://office365-expired-password.com/update",
    "http://zoom-meeting-join-now.free-app.com/invite",
    "http://your-account-limited-paypal.com/restore",
    "http://amazon-delivery-problem.verify.net/track",
    "http://dhl-package-hold-fee.com/pay-now",
    "http://fedex-delivery-alert.phish.biz/track",
    "http://ubs-bank-login.secure-online-banking.net",
    "http://crypto-wallet-verify.free-bitcoin.com",
    "http://blockchain-account-secure.phish.io/login",
    "http://coinbase-verify-id.com/signin?user=123",
    "http://binance-kyc-verify.net/update",
    "http://gmail-security-alert-login.com/verify",
    "http://yahoo-mail-update-account.com/login",
    "http://icloud-locked-account.apple-verify.com",
    "http://support-microsoft-helpdesk.com/remote",
    "http://secure.login-bankwire-transfer.com",
    "http://urgent-account-suspend.verify-today.net",
    "http://your-visa-card-blocked.bank-alert.com",
]


def build_dataset():
    """Combine legitimate and phishing URLs into a labelled DataFrame."""
    rows = []
    for url in LEGITIMATE_URLS:
        feats = extract_features(url)
        rows.append(feats + [0])   # 0 = legitimate

    for url in PHISHING_URLS:
        feats = extract_features(url)
        rows.append(feats + [1])   # 1 = phishing

    # ------------------------------------------------------------------
    # Augment with programmatically generated samples for better coverage
    # ------------------------------------------------------------------
    random.seed(42)

    # Generate 200 more legitimate-style URLs
    legit_domains = ["google", "amazon", "github", "microsoft", "apple",
                     "facebook", "twitter", "linkedin", "youtube", "netflix"]
    tlds = [".com", ".org", ".net", ".io", ".co"]
    for _ in range(200):
        domain = random.choice(legit_domains) + random.choice(tlds)
        path = "/" + "/".join(
            random.choice(["docs", "help", "account", "settings", "search"])
            for _ in range(random.randint(0, 2))
        )
        url = f"https://www.{domain}{path}"
        rows.append(extract_features(url) + [0])

    # Generate 200 more phishing-style URLs
    phish_words = ["secure", "verify", "login", "account", "update",
                   "confirm", "bank", "paypal", "alert", "urgent"]
    phish_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".info", ".biz"]
    for _ in range(200):
        word1 = random.choice(phish_words)
        word2 = random.choice(phish_words)
        tld = random.choice(phish_tlds)
        path = "/login?user=victim&token=" + str(random.randint(10000, 99999))
        scheme = random.choice(["http", "https"])
        url = f"{scheme}://{word1}-{word2}{tld}{path}"
        rows.append(extract_features(url) + [1])

    cols = FEATURE_NAMES + ["label"]
    df = pd.DataFrame(rows, columns=cols)
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 3. TRAIN & SAVE
# ─────────────────────────────────────────────────────────────────────────────

def train_and_save():
    print("📊  Building dataset …")
    df = build_dataset()
    print(f"    Total samples : {len(df)}")
    print(f"    Phishing      : {df['label'].sum()}")
    print(f"    Legitimate    : {(df['label'] == 0).sum()}")

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Pipeline: scaling + Random Forest
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42,
            class_weight="balanced",
        )),
    ])

    print("\n🚀  Training Random Forest …")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n✅  Test Accuracy : {acc * 100:.2f}%")
    print("\n📋  Classification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=["Legitimate", "Phishing"]))

    # Save model
    out_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(out_dir, "phishing_model.pkl")
    joblib.dump(pipeline, model_path)
    print(f"\n💾  Model saved → {model_path}")
    return model_path


if __name__ == "__main__":
    train_and_save()
