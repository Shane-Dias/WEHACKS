from django.urls import path
from . import views

urlpatterns = [
    path('report-incident/', views.form_report.as_view(), name='report_incident'),
    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('api/login/', views.LoginView.as_view(), name='login'),
    path("all_user_incidents/", views.all_user_incidents, name="all_user_incidents"),
    path("api/user/<int:user_id>/", views.UserDetailView.as_view(), name="user-detail"),
    path("voice-report/", views.voicereport.as_view(), name="user-detail"),
]

