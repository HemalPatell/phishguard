"""
ml_model.py
-----------
Loads the pre-trained model and exposes a predict() function.
Uses a module-level singleton so the model is loaded only once
when Django starts (not on every request).
"""

import numpy as np
import joblib
from django.conf import settings
from .feature_extractor import extract_features

# ── Load model once at import time ──────────────────────────────────────────
_model = None

def _load_model():
    global _model
    if _model is None:
        model_path = settings.ML_MODEL_PATH
        _model = joblib.load(model_path)
    return _model


def predict(url: str) -> dict:
    """
    Predict whether a URL is phishing or legitimate.

    Returns:
        {
            "label":      "Phishing" | "Legitimate",
            "is_phishing": True | False,
            "confidence":  float (0-100),
            "features":    dict of feature_name → value,
        }
    """
    model = _load_model()
    features = extract_features(url)
    X = np.array(features).reshape(1, -1)

    # predict_proba returns [[prob_legit, prob_phishing]]
    proba = model.predict_proba(X)[0]
    pred_class = int(model.predict(X)[0])

    is_phishing = pred_class == 1
    confidence = float(proba[pred_class]) * 100   # confidence in predicted class

    return {
        "label":       "Phishing" if is_phishing else "Legitimate",
        "is_phishing": is_phishing,
        "confidence":  round(confidence, 2),
        "features":    dict(zip(
            ["url_length","hostname_length","ip_in_url","uses_https",
             "dot_count","hyphen_count","at_symbol_count","subdomain_count",
             "suspicious_count","path_depth","has_query","has_double_slash"],
            features
        )),
    }
