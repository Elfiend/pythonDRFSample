from django.contrib.auth import password_validation

from rest_framework import serializers
from rest_framework.authtoken.models import Token

from .models import LocalUser, LocalUserManager


class EmptySerializer(serializers.Serializer):
    """
    A empty serializer as the default setting.
    """
    pass


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    A user serializer for registering the user.
    """

    class Meta:
        model = LocalUser
        fields = ('id', 'email', 'password')

    def validate_email(self, value):
        user = LocalUser.objects.filter(email=value)
        if user:
            raise serializers.ValidationError('Email is already taken')
        return LocalUserManager.normalize_email(value)

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value


class UserLoginSerializer(serializers.Serializer):
    """
    A user serializer for login.
    """
    email = serializers.CharField(max_length=300, required=True)
    password = serializers.CharField(required=True, write_only=True)


class AuthUserSerializer(serializers.ModelSerializer):
    """
    A user serializer for auth the user.
    """
    auth_token = serializers.SerializerMethodField()

    class Meta:
        model = LocalUser
        fields = ('id', 'email', 'is_active', 'is_staff', 'auth_token')
        read_only_fields = ('id', 'email', 'is_active', 'is_staff')

    def get_auth_token(self, obj):
        token, _ = Token.objects.get_or_create(user=obj)
        return token.key


class PasswordChangeSerializer(serializers.Serializer):
    """
    A user serializer for changing password.
    """
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_current_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError('Current password does not match')
        return value

    def validate_new_password(self, value):
        password_validation.validate_password(value)
        return value


class UserListSerializer(serializers.ModelSerializer):
    """
    A user serializer for list about user detail.
    """

    class Meta:
        model = LocalUser
        fields = (
            'email',
            'date_joined',
            'login_count',
            'last_login',
        )
