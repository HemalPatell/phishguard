"""
views.py
--------
Handles URL form submission, ML prediction, history display,
and a JSON API endpoint.
"""

import json
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator

from .forms import URLScanForm
from .models import URLScan
from .ml_model import predict


# ── Home / Scan page ────────────────────────────────────────────────────────

@login_required
def index(request):
    """
    GET  → show the URL input form + recent scan stats.
    POST → validate URL, run prediction, save to DB, redirect to result.
    """
    form = URLScanForm()

    # Stats for the dashboard cards
    total_scans    = URLScan.objects.count()
    phishing_count = URLScan.objects.filter(result="phishing").count()
    legit_count    = URLScan.objects.filter(result="legitimate").count()
    recent_scans   = URLScan.objects.all()[:5]

    if request.method == "POST":
        form = URLScanForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data["url"]

            # --- Run the ML model ---
            result = predict(url)

            # --- Persist to database ---
            scan = URLScan.objects.create(
                url          = url,
                result       = "phishing" if result["is_phishing"] else "legitimate",
                confidence   = result["confidence"],
                user         = request.user if request.user.is_authenticated else None,
                features_json= result["features"],
            )

            # Redirect to result page (POST-Redirect-GET pattern)
            return redirect("detector:result", pk=scan.pk)

    context = {
        "form":          form,
        "total_scans":   total_scans,
        "phishing_count":phishing_count,
        "legit_count":   legit_count,
        "recent_scans":  recent_scans,
    }
    return render(request, "detector/index.html", context)


# ── Result page ─────────────────────────────────────────────────────────────

@login_required
def result(request, pk):
    """Display the analysis result for a specific scan."""
    try:
        scan = URLScan.objects.get(pk=pk)
    except URLScan.DoesNotExist:
        return redirect("detector:index")

    # Pretty-print feature names for the UI
    feature_labels = {
        "url_length":       "URL Length",
        "hostname_length":  "Hostname Length",
        "ip_in_url":        "IP Address in URL",
        "uses_https":       "Uses HTTPS",
        "dot_count":        "Number of Dots",
        "hyphen_count":     "Number of Hyphens",
        "at_symbol_count":  "@ Symbols",
        "subdomain_count":  "Subdomains",
        "suspicious_count": "Suspicious Keywords",
        "path_depth":       "Path Depth",
        "has_query":        "Has Query String",
        "has_double_slash": "Double-Slash in Path",
    }

    features_display = []
    if scan.features_json:
        for key, val in scan.features_json.items():
            features_display.append({
                "name":  feature_labels.get(key, key),
                "value": val,
                "key":   key,
            })

    return render(request, "detector/result.html", {
        "scan":             scan,
        "features_display": features_display,
    })


# ── History page ─────────────────────────────────────────────────────────────

@login_required
def history(request):
    """Paginated list of all scanned URLs."""
    scan_list = URLScan.objects.all()

    # Optional filter
    filter_type = request.GET.get("filter", "all")
    if filter_type == "phishing":
        scan_list = scan_list.filter(result="phishing")
    elif filter_type == "legitimate":
        scan_list = scan_list.filter(result="legitimate")

    paginator = Paginator(scan_list, 15)
    page_obj  = paginator.get_page(request.GET.get("page"))

    return render(request, "detector/history.html", {
        "page_obj":    page_obj,
        "filter_type": filter_type,
        "total":       URLScan.objects.count(),
        "phishing":    URLScan.objects.filter(result="phishing").count(),
        "legit":       URLScan.objects.filter(result="legitimate").count(),
    })


# ── REST API endpoint ────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(["POST"])
def api_predict(request):
    """
    POST /api/predict/
    Body (JSON): {"url": "https://example.com"}

    Returns:
        {"url": "...", "label": "Phishing"|"Legitimate",
         "is_phishing": true|false, "confidence": 97.3,
         "features": {...}}
    """
    try:
        data = json.loads(request.body)
        url  = data.get("url", "").strip()
        if not url:
            return JsonResponse({"error": "url field is required."}, status=400)

        result = predict(url)

        # Optionally save to DB (API calls attributed to no user)
        URLScan.objects.create(
            url          = url,
            result       = "phishing" if result["is_phishing"] else "legitimate",
            confidence   = result["confidence"],
            features_json= result["features"],
        )

        return JsonResponse({"url": url, **result})

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON body."}, status=400)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)
