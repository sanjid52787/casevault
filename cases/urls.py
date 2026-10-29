"""
CaseVault Case Management URLs
"""

from django.urls import path

from cases import views

urlpatterns = [
    path('', views.case_list_view, name='case_list'),
    path('new/', views.case_create_view, name='case_create'),
    path('<uuid:case_id>/', views.case_detail_view, name='case_detail'),
    path('<uuid:case_id>/notes/add/', views.case_add_note_view, name='case_add_note'),
    path('<uuid:case_id>/members/add/', views.case_add_member_view, name='case_add_member'),
]

