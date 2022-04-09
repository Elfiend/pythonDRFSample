import json
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import login, logout
from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie

import requests
from rest_framework import generics, permissions, status, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.reverse import reverse

from .models import LocalUser
from .permissions import IsEmailConfirmed
from .serializers import (AuthUserSerializer, EmptySerializer,
                          ResetPasswordSerializer, UpdateProfileSerializer,
                          UserListSerializer, UserLoginSerializer,
                          UserSignupSerializer)
from .utils import (activate_account, create_user_account,
                    get_and_authenticate_user, send_verification_email,
                    update_name)


class AuthViewSet(viewsets.GenericViewSet):
    """
    A set of the view used for authenticate.
    """
    permission_classes = (AllowAny,)
    authentication_classes = (SessionAuthentication,)

    serializer_class = EmptySerializer
    serializer_classes = {
        'signup': UserSignupSerializer,
        'login': UserLoginSerializer,
        'reset_password': ResetPasswordSerializer,
        'update_profile': UpdateProfileSerializer,
    }
    queryset = ''

    @action(methods=[
        'POST',
    ], detail=False)
    def signup(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = create_user_account(**serializer.validated_data)
        # Send email
        send_verification_email(request, user)
        data = AuthUserSerializer(user).data
        return Response(data=data, status=status.HTTP_201_CREATED)

    @action(methods=[
        'POST',
    ], detail=False)
    def login(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_and_authenticate_user(**serializer.validated_data)
        user.login_count += 1
        user.save()
        data = AuthUserSerializer(user).data
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=[
        'POST',
    ], detail=False)
    def logout(self, request):
        try:
            user = request.user
            # https://auth0.com/docs/quickstart/webapp/django
            if user.is_social_auth is True:
                domain = settings.SOCIAL_AUTH_AUTH0_DOMAIN
                data = urlencode({
                    'returnTo': request.build_absolute_uri('/'),
                    'client_id': settings.SOCIAL_AUTH_AUTH0_KEY
                })
                logout_url = f'https://{domain}/v2/logout?{data}'
                response = requests.get(logout_url)
                json_response = json.loads(response.text)
                print(json_response)
        except AttributeError:
            data = {'error': ''}
            return Response(data=data, status=status.HTTP_200_OK)

        logout(request)
        data = {'success': 'Sucessfully logged out'}
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['POST'],
            detail=False,
            permission_classes=[
                IsAuthenticated,
            ])
    def reset_password(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST'],
            detail=False,
            permission_classes=[
                IsAuthenticated,
            ])
    def resend_verification_email(self, request):
        user = request.user
        send_verification_email(request, user)
        data = {'success': 'Please Confirm your email to complete registration'}
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['GET'],
            detail=False,
            name='email-verification',
            url_path='email_verification/'
            r'(?P<uidb64>[-a-zA-Z0-9_]+)/'
            r'(?P<token>[-a-zA-Z0-9_]+)/')
    def email_verification(self, request, uidb64, token):
        success, user = activate_account(uidb64, token)
        if success is False:
            data = {'error': 'The confirmation link was invalid.'}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)
        login(request, user)
        data = AuthUserSerializer(user).data
        data['success'] = 'Your account have been confirmed.'
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['POST'],
            detail=False,
            permission_classes=[
                IsAuthenticated,
            ])
    def update_profile(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        success = update_name(request.user, **serializer.validated_data)
        if success is False:
            data = {'error': 'Update social name failed.'}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)
        data = AuthUserSerializer(request.user).data
        data['success'] = 'Your name updated.'
        return Response(data=data, status=status.HTTP_200_OK)

    def get_serializer_class(self):
        if not isinstance(self.serializer_classes, dict):
            raise ImproperlyConfigured(
                'serializer_classes should be a dict mapping.')

        if self.action in self.serializer_classes:
            return self.serializer_classes[self.action]
        return super().get_serializer_class()

    def list(self, request):
        return Response({
            'signup': reverse('auth-signup', request=request),
            'login': reverse('auth-login', request=request),
            'reset_password': reverse('auth-reset-password', request=request),
            'logout': reverse('auth-logout', request=request),
        })


class UserList(generics.ListAPIView):
    queryset = LocalUser.objects.all()
    serializer_class = UserListSerializer
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)


@ensure_csrf_cookie
def set_csrf_cookie(request):
    """
    This will be `/api/auth/set-csrf-cookie/` on `urls.py`
    """
    del request
    data = {'details': 'CSRF cookie set'}
    return JsonResponse(data)
