from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import RegisterView, KeyMeView, PublicKeyListView, ABEParametersView, DocumentViewSet, change_password

router = DefaultRouter()
router.register(r'documents', DocumentViewSet, basename='document')

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', TokenObtainPairView.as_view(), name='login'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('keys/me/', KeyMeView.as_view(), name='key_me'),
    path('auth/change-password/', change_password, name='change_password'),
    path('keys/public/', PublicKeyListView.as_view(), name='public_keys'),
    path('keys/abe/parameters/', ABEParametersView.as_view(), name='abe_parameters'),
    path('', include(router.urls)),
]
