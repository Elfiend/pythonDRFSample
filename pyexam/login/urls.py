"""
Url List:
^swagger(?P<format>.json|.yaml)$ [name='schema-json']
^swagger/$ [name='schema-swagger-ui']
^redoc/$ [name='schema-redoc']
users/ [name='user-list']
users/<int:pk>/ [name='user-detail']
api/login/social/token
^api/auth$ [name='auth-list']
^api/auth/email_verification/<uidb64>/<token>/$ [name='auth-email-verification']
^api/auth/login$ [name='auth-login']
^api/auth/logout$ [name='auth-logout']
^api/auth/resend_verification_email$ [name='auth-resend-verification-email']
^api/auth/reset_password$ [name='auth-reset-password']
^api/auth/signup$ [name='auth-signup']
^api/auth/update_profile$ [name='auth-update-profile']
^$ [name='api-root']
"""
from django.urls import include, path

from rest_framework import routers
from rest_framework.urlpatterns import format_suffix_patterns

from .views import AuthViewSet, UserList

router = routers.DefaultRouter(trailing_slash=False)
router.register(r'api/auth', AuthViewSet, basename='auth')

urlpatterns = [
    path('api/users/', UserList.as_view(), name='user-list'),
    path('', router.get_api_root_view()),
    path('api/login/', include('rest_social_auth.urls_token')),
]

urlpatterns = format_suffix_patterns(urlpatterns)
urlpatterns += router.urls
