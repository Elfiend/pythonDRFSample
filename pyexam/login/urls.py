"""
Url List:
- api/auth/login
- api/auth/logout
- api/auth/password_change
- api/auth/register
"""
from django.urls import path

from rest_framework import routers
from rest_framework.urlpatterns import format_suffix_patterns

from .views import AuthViewSet, UserList

router = routers.DefaultRouter(trailing_slash=False)
router.register(r'api/auth', AuthViewSet, basename='auth')

urlpatterns = [
    path('api/users/', UserList.as_view(), name='user-list'),
    path('', router.get_api_root_view()),
]

urlpatterns = format_suffix_patterns(urlpatterns)
urlpatterns += router.urls
