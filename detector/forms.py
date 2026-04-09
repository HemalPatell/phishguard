"""
forms.py – URL submission form.
"""

from django import forms


class URLScanForm(forms.Form):
    url = forms.URLField(
        label="",
        max_length=2048,
        widget=forms.URLInput(attrs={
            "class":       "form-control form-control-lg",
            "placeholder": "https://example.com/path?query=value",
            "autofocus":   True,
        }),
        error_messages={"required": "Please enter a URL.",
                        "invalid":  "Please enter a valid URL (include http:// or https://)."},
    )
