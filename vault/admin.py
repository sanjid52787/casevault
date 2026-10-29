"""
Django Admin Configuration for Evidence Vault
"""

from django.contrib import admin

from vault.models import EvidenceItem


@admin.register(EvidenceItem)
class EvidenceItemAdmin(admin.ModelAdmin):
    list_display = ('original_filename', 'case', 'uploaded_by', 'file_size_bytes', 'mime_type', 'sha256_hash', 'uploaded_at')
    list_filter = ('mime_type', 'uploaded_at')
    search_fields = ('original_filename', 'case__case_number', 'sha256_hash', 'sha512_hash')
    readonly_fields = ('id', 'storage_filename', 'file_size_bytes', 'sha256_hash', 'sha512_hash', 'uploaded_at')
