from django.contrib import admin
from .models import URLScan

@admin.register(URLScan)
class URLScanAdmin(admin.ModelAdmin):
    list_display  = ("url", "result", "confidence", "user", "scanned_at")
    list_filter   = ("result", "scanned_at")
    search_fields = ("url",)
    readonly_fields = ("scanned_at", "features_json")
