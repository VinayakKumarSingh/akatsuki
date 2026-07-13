from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView, KeyMeView, PublicKeyListView, ABEParametersView, DocumentViewSet, change_password,
    request_access, list_pending_requests, approve_request, deny_request,
    CustomTokenObtainPairView, setup_2fa, verify_2fa, disable_2fa, AuditLogViewSet, GroupViewSet,
    get_security_question, verify_security_answer, reset_password_with_recovery
)

router = DefaultRouter()
router.register(r'documents', DocumentViewSet, basename='document')
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')
router.register(r'groups', GroupViewSet, basename='group')

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='login'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('keys/me/', KeyMeView.as_view(), name='key_me'),
    path('auth/change-password/', change_password, name='change_password'),
    path('auth/forgot-password/question/', get_security_question, name='forgot_password_question'),
    path('auth/forgot-password/verify/', verify_security_answer, name='forgot_password_verify'),
    path('auth/forgot-password/reset/', reset_password_with_recovery, name='forgot_password_reset'),
    path('keys/public/', PublicKeyListView.as_view(), name='public_keys'),
    path('keys/abe/parameters/', ABEParametersView.as_view(), name='abe_parameters'),
    
    # Access Request Workflow Routes
    path('documents/<uuid:doc_id>/request-access/', request_access, name='request_access'),
    path('requests/pending/', list_pending_requests, name='list_pending_requests'),
    path('requests/<uuid:req_id>/approve/', approve_request, name='approve_request'),
    path('requests/<uuid:req_id>/deny/', deny_request, name='deny_request'),
    
    # 2FA Routes
    path('auth/2fa/setup/', setup_2fa, name='setup_2fa'),
    path('auth/2fa/verify/', verify_2fa, name='verify_2fa'),
    path('auth/2fa/disable/', disable_2fa, name='disable_2fa'),
    
    path('', include(router.urls)),
]
