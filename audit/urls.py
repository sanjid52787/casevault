"""
CaseVault Audit Trail URLs
"""

from django.urls import path

from audit import views

urlpatterns = [
    path('', views.audit_log_view, name='audit_log'),
]

