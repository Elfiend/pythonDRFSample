from django.contrib.auth import login, logout
from django.core.exceptions import ImproperlyConfigured

from rest_framework import generics, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.reverse import reverse

from .models import LocalUser
from .permissions import IsEmailConfirmed
from .serializers import (AuthUserSerializer, EmptySerializer,
                          PasswordChangeSerializer, UserListSerializer,
                          UserLoginSerializer, UserRegisterSerializer)
from .utils import (activate_account, create_user_account,
                    get_and_authenticate_user, send_verification_email)


class AuthViewSet(viewsets.GenericViewSet):
    """
    A set of the view used for authenticate.
    """
    permission_classes = [
        AllowAny,
    ]
    serializer_class = EmptySerializer
    serializer_classes = {
        'login': UserLoginSerializer,
        'register': UserRegisterSerializer,
        'password_change': PasswordChangeSerializer,
    }
    queryset = ''

    @action(methods=[
        'POST',
    ], detail=False)
    def register(self, request):
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
            request.user.auth_token.delete()
        except (AttributeError):
            pass

        logout(request)
        data = {'success': 'Sucessfully logged out'}
        return Response(data=data, status=status.HTTP_200_OK)

    @action(methods=['POST'],
            detail=False,
            permission_classes=[
                IsAuthenticated,
            ])
    def password_change(self, request):
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

    @action(
        methods=['GET'],
        detail=False,
        name='email-verification',
        url_path=
        r'email_verification/(?P<uidb64>[-a-zA-Z0-9_]+)/(?P<token>[-a-zA-Z0-9_]+)/'
    )
    def email_verification(self, request, uidb64, token):
        success, user = activate_account(uidb64, token)
        if success is False:
            data = {'error': 'The confirmation link was invalid.'}
            return Response(data=data, status=status.HTTP_400_BAD_REQUEST)
        login(request, user)
        data = AuthUserSerializer(user).data
        data['success'] = 'Your account have been confirmed.'
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
            'register': reverse('auth-register', request=request),
            'login': reverse('auth-login', request=request),
            'password_change': reverse('auth-password-change', request=request),
            'logout': reverse('auth-logout', request=request),
        })


class UserList(generics.ListAPIView):
    queryset = LocalUser.objects.all()
    serializer_class = UserListSerializer
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
