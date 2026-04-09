"""
models.py – database models for URL scan history.
"""

from django.db import models
from django.contrib.auth.models import User


class URLScan(models.Model):
    """Stores every URL that has been analysed."""

    RESULT_CHOICES = [
        ("phishing",   "Phishing"),
        ("legitimate", "Legitimate"),
    ]

    url        = models.URLField(max_length=2048, verbose_name="Scanned URL")
    result     = models.CharField(max_length=20, choices=RESULT_CHOICES)
    confidence = models.FloatField(help_text="Confidence score (0–100)")
    scanned_at = models.DateTimeField(auto_now_add=True)

    # Optional: link to the logged-in user (null if anonymous)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="scans",
    )

    # Feature snapshot (JSON-serialised for transparency)
    features_json = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-scanned_at"]
        verbose_name = "URL Scan"
        verbose_name_plural = "URL Scans"

    def __str__(self):
        return f"[{self.result.upper()}] {self.url[:60]}"

    @property
    def is_phishing(self):
        return self.result == "phishing"

    @property
    def confidence_color(self):
        """Bootstrap colour class based on result and confidence."""
        if self.is_phishing:
            return "danger"
        return "success"
