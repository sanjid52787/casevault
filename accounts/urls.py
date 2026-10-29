"""
CaseVault Authentication URL Configuration
"""

from django.urls import path

from accounts import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('mfa/verify/', views.mfa_verify_view, name='mfa_verify'),
    path('mfa/setup/', views.mfa_setup_view, name='mfa_setup'),
]

