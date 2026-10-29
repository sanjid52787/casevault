"""
Django Admin Configuration for CustomUser
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from accounts.models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'role', 'organization', 'is_mfa_enabled', 'is_active', 'is_staff')
    list_filter = ('role', 'is_mfa_enabled', 'is_staff', 'is_active', 'organization')
    search_fields = ('username', 'email', 'organization')
    ordering = ('username',)

    fieldsets = UserAdmin.fieldsets + (
        ('CaseVault Governance & RBAC', {
            'fields': ('role', 'organization', 'is_mfa_enabled', 'totp_secret', 'failed_login_attempts', 'locked_until')
        }),
    )
