"""pyexam URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path, re_path

from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

detail_description = """
Source code : https://github.com/Elfiend/pythonDRFSample
Login Way:
    1. Use session(Django Login button) with username and password. 
    2. Use token(Authorize button) 
        a. Login with api, and get the result token.
        b. Press the button and fill the token value with prefix "Token " 
        Examples: token is 123456, Enter the value "Token 123456"
"""

SchemaView = get_schema_view(
    openapi.Info(
        title='Django Restful framework API',
        default_version='v1',
        description=detail_description,
        terms_of_service='https://www.google.com/policies/terms/',
        contact=openapi.Contact(email='elfiend+drf@gmail.com'),
        license=openapi.License(name='BSD License'),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    re_path(r'^swagger(?P<format>\.json|\.yaml)$',
            SchemaView.without_ui(cache_timeout=0),
            name='schema-json'),
    re_path(r'^swagger/$',
            SchemaView.with_ui('swagger', cache_timeout=0),
            name='schema-swagger-ui'),
    re_path(r'^redoc/$',
            SchemaView.with_ui('redoc', cache_timeout=0),
            name='schema-redoc'),
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls')),
    path('', include('login.urls')),
]
