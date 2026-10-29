"""
CaseVault Evidence Vault URLs
"""

from django.urls import path

from vault import views

urlpatterns = [
    path('<uuid:case_id>/upload/', views.evidence_upload_view, name='evidence_upload'),
    path('<uuid:case_id>/download/<uuid:evidence_id>/', views.evidence_download_view, name='evidence_download'),
]

