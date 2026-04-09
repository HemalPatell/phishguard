"""
URL patterns for the detector app.
"""

from django.urls import path
from . import views

app_name = "detector"

urlpatterns = [
    path("",              views.index,      name="index"),
    path("result/<int:pk>/", views.result,  name="result"),
    path("history/",      views.history,    name="history"),
    path("api/predict/",  views.api_predict, name="api_predict"),
]
