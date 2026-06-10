from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    RegisterView, KeyMeView, PublicKeyListView, ABEParametersView, DocumentViewSet, change_password,
    get_security_question, verify_security_answer, reset_password_with_recovery
)

router = DefaultRouter()
router.register(r'documents', DocumentViewSet, basename='document')

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', TokenObtainPairView.as_view(), name='login'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('keys/me/', KeyMeView.as_view(), name='key_me'),
    path('auth/change-password/', change_password, name='change_password'),
    path('auth/forgot-password/question/', get_security_question, name='forgot_password_question'),
    path('auth/forgot-password/verify/', verify_security_answer, name='forgot_password_verify'),
    path('auth/forgot-password/reset/', reset_password_with_recovery, name='forgot_password_reset'),
    path('keys/public/', PublicKeyListView.as_view(), name='public_keys'),
    path('keys/abe/parameters/', ABEParametersView.as_view(), name='abe_parameters'),
    path('', include(router.urls)),
]
