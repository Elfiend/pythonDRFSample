import logging
import sys

from django.contrib.auth import login, logout
from django.core.exceptions import ImproperlyConfigured

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics, permissions, status, viewsets
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
                    get_active_session_amount, get_and_authenticate_user,
                    get_average_active_user_amount, get_signed_up_user_amount,
                    increase_login_count, send_verification_email,
                    update_active_day, update_name)

logger = logging.getLogger(__name__)


class AuthViewSet(viewsets.GenericViewSet):
    """
    A set of the view used for authenticate.
    """
    permission_classes = (AllowAny,)

    serializer_class = EmptySerializer
    serializer_classes = {
        'signup': UserSignupSerializer,
        'login': UserLoginSerializer,
        'reset_password': ResetPasswordSerializer,
        'update_profile': UpdateProfileSerializer,
    }
    queryset = ''

    @swagger_auto_schema(
        responses={
            status.HTTP_201_CREATED:
                openapi.Response(
                    description='Sign up successful and return user detail.',
                    schema=AuthUserSerializer,
                    examples=AuthUserSerializer.to_string_response_examples(),
                ),
            status.HTTP_400_BAD_REQUEST:
                openapi.Response(
                    description='Sign up failed with error message.',
                    examples=UserSignupSerializer.to_string_response_examples()
                ),
        })
    @action(methods=[
        'POST',
    ], detail=False)
    def signup(self, request):
        """
        Sign up with email and password.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = create_user_account(**serializer.validated_data)
        # Send email
        send_verification_email(user)
        update_active_day(user)
        data = AuthUserSerializer(user).data
        return Response(data=data, status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK:
                openapi.Response(
                    description='Login successful and return user detail.',
                    schema=AuthUserSerializer,
                    examples=AuthUserSerializer.to_string_response_examples(),
                ),
            status.HTTP_400_BAD_REQUEST:
                openapi.Response(
                    description='Login failed with error message.',
                    examples=UserLoginSerializer.to_string_response_examples(),
                ),
        })
    @action(methods=[
        'POST',
    ], detail=False)
    def login(self, request):
        """
        Log in with email and password.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = get_and_authenticate_user(**serializer.validated_data)
        increase_login_count(user)
        update_active_day(user)
        logger.info(user)
        data = AuthUserSerializer(user).data
        return Response(data=data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        responses={
            status.HTTP_204_NO_CONTENT:
                openapi.Response(description='Log out successful.',
                                 schema=EmptySerializer)
        })
    @action(methods=[
        'POST',
    ],
            detail=False,
            permission_classes=[
                IsAuthenticated,
            ])
    def logout(self, request):
        """
        Log out the user by both email and social account.
        """
        try:
            user = request.user
            logger.info(user)
        except AttributeError:
            # Log out error but need not tell client.
            # Just do log with error detail.
            logger.error('%s', ' '.join(sys.argv), exc_info=sys.exc_info())
            return Response(status=status.HTTP_204_NO_CONTENT)

        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @swagger_auto_schema(
        responses={
            status.HTTP_204_NO_CONTENT:
                openapi.Response(
                    description='Reset password successful.',
                    schema=EmptySerializer,
                ),
            status.HTTP_400_BAD_REQUEST:
                openapi.Response(
                    description='Reset password failed with error message.',
                    examples=ResetPasswordSerializer.
                    to_string_response_examples())
        })
    @action(methods=[
        'POST',
    ],
            detail=False,
            permission_classes=[
                IsAuthenticated,
            ])
    def reset_password(self, request):
        """
        Reset password with new password directly.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @swagger_auto_schema(
        responses={
            status.HTTP_204_NO_CONTENT:
                openapi.Response(
                    description='Send email successful.',
                    schema=EmptySerializer,
                ),
        })
    @action(methods=[
        'POST',
    ],
            detail=False,
            permission_classes=[
                IsAuthenticated,
            ])
    def resend_verification_email(self, request):
        """
        Send verification email again.
        """
        user = request.user
        send_verification_email(user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @swagger_auto_schema(
        responses={
            status.HTTP_204_NO_CONTENT:
                openapi.Response(
                    description='Verify email successful and log in user.',
                    schema=AuthUserSerializer,
                    examples=AuthUserSerializer.to_string_response_examples(),
                ),
            status.HTTP_400_BAD_REQUEST:
                openapi.Response(
                    description='Verify email failed with error message.',
                    examples={
                        'application/json': {
                            'error': 'The confirmation link was invalid.'
                        }
                    })
        })
    @action(methods=[
        'GET',
    ],
            detail=False,
            name='email-verification',
            url_path='email_verification/'
            r'(?P<uidb64>[-a-zA-Z0-9_]+)/'
            r'(?P<token>[-a-zA-Z0-9_]+)/')
    def email_verification(self, request, uidb64, token):
        """
        Verify the user from email link.
        """
        success, user = activate_account(uidb64, token)
        if success is False:
            data = {'error': 'The confirmation link was invalid.'}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)
        login(request, user)
        update_active_day(user)
        data = AuthUserSerializer(user).data
        return Response(data=data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK:
                openapi.Response(
                    description='Update successful and return user detail.',
                    schema=AuthUserSerializer,
                    examples=AuthUserSerializer.to_string_response_examples(),
                ),
            status.HTTP_400_BAD_REQUEST:
                openapi.Response(
                    description='Login failed with error message.',
                    examples={
                        'application/json': {
                            'error': 'Update social name failed.'
                        }
                    },
                ),
        })
    @action(methods=[
        'POST',
    ],
            detail=False,
            permission_classes=[
                IsAuthenticated,
            ])
    def update_profile(self, request):
        """
        Update the name.
        The default name is empty string if user sign up with email.
        Otherwise, the default name is from the social account.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        success = update_name(request.user, **serializer.validated_data)
        if success is False:
            data = {'error': 'Update social name failed.'}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)
        update_active_day(request.user)
        data = AuthUserSerializer(request.user).data
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


class UserDataViewSet(viewsets.GenericViewSet):
    """
    A set of the view used for user data.
    """
    permission_classes = (AllowAny,)
    serializer_class = EmptySerializer
    queryset = LocalUser.objects.all()

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK:
                openapi.Response(
                    description='query successful and return users statistics.',
                    examples={
                        'application/json': {
                            'sign_up_users': 10,
                            'active_users': 5,
                            'average_user': 3,
                        }
                    },
                ),
        })
    @action(methods=[
        'GET',
    ], detail=False)
    def get_statistics(self, request):
        del request
        data = {
            'sign_up_users': get_signed_up_user_amount(),
            'active_users': get_active_session_amount(),
            'average_user': get_average_active_user_amount(),
        }
        return Response(data=data, status=status.HTTP_200_OK)
