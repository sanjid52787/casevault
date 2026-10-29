"""
Django Admin Configuration for Case Management
"""

from django.contrib import admin

from cases.models import Case, CaseMembership, CaseNote


class CaseMembershipInline(admin.TabularInline):
    model = CaseMembership
    extra = 1


class CaseNoteInline(admin.TabularInline):
    model = CaseNote
    extra = 0
    readonly_fields = ('author', 'created_at')


@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ('case_number', 'title', 'client_organization', 'classification', 'status', 'lead_investigator', 'created_at')
    list_filter = ('classification', 'status', 'client_organization')
    search_fields = ('case_number', 'title', 'description', 'client_organization')
    inlines = [CaseMembershipInline, CaseNoteInline]


@admin.register(CaseMembership)
class CaseMembershipAdmin(admin.ModelAdmin):
    list_display = ('case', 'user', 'role_in_case', 'assigned_at')
    list_filter = ('role_in_case',)
    search_fields = ('case__case_number', 'user__username')


@admin.register(CaseNote)
class CaseNoteAdmin(admin.ModelAdmin):
    list_display = ('case', 'author', 'is_client_visible', 'created_at')
    list_filter = ('is_client_visible', 'created_at')
    search_fields = ('case__case_number', 'author__username', 'note')
