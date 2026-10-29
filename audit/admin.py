"""
Django Admin Configuration for AuditLog (Read-Only Enforcement)
"""

from django.contrib import admin
from audit.models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'timestamp', 'action', 'actor_username', 'ip_address', 'target_model', 'target_id')
    list_filter = ('action', 'timestamp')
    search_fields = ('actor_username', 'ip_address', 'target_id', 'details')
    readonly_fields = ('id', 'timestamp', 'actor', 'actor_username', 'ip_address', 'action',
                       'target_model', 'target_id', 'details', 'previous_hash', 'current_hash')
    ordering = ('-id',)

    def has_add_permission(self, request):
        # Audit records can only be created via the audit logging service
        return False

    def has_change_permission(self, request, obj=None):
        # Audit records are immutable
        return False

    def has_delete_permission(self, request, obj=None):
        # Audit records cannot be deleted through admin interface
        return False
