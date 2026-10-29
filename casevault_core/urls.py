"""
CaseVault URL Configuration
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)
"""

from django.contrib import admin
from django.shortcuts import redirect
from django.urls import include, path


def root_redirect(request):
    if request.user.is_authenticated:
        return redirect('case_list')
    return redirect('login')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', root_redirect, name='root'),
    path('auth/', include('accounts.urls')),
    path('cases/', include('cases.urls')),
    path('vault/', include('vault.urls')),
    path('audit/', include('audit.urls')),
]
