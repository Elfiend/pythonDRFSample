from django.contrib.auth import password_validation

from rest_framework import serializers
from rest_framework.authtoken.models import Token

from .models import LocalUser, LocalUserManager, Profile


class EmptySerializer(serializers.Serializer):
    """
    A empty serializer as the default setting.
    """
    pass


class UserSignupSerializer(serializers.ModelSerializer):
    """
    A user serialize for signing up the user.
    """
    password2 = serializers.CharField(required=True)

    class Meta:
        model = LocalUser
        fields = ('email', 'password', 'password2')

    def validate_email(self, value):
        user = LocalUser.objects.filter(email=value)
        if user:
            raise serializers.ValidationError('Email is already taken')
        return LocalUserManager.normalize_email(value)

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value

    def validate(self, attrs):
        if attrs.get('password2') != attrs.get('password'):
            raise serializers.ValidationError(
                {'password2': 'The two password fields did not match.'})
        # Drop the unnecessary key for creating.
        attrs.pop('password2')
        return attrs

    @staticmethod
    def to_string_response_examples():
        return {
            'application/json': {
                'email': ['Email is already taken'],
                'password': [
                    'This password is too short. It must contain at least 8 characters.',
                    'The password must contain at least 1 digit, 0-9.',
                    'The password must contain at least 1 uppercase letter, A-Z.',
                    'The password must contain at least 1 lowercase letter, a-z.'
                ],
                'password2': ['The two password fields did not match.',]
            }
        }


class UserLoginSerializer(serializers.Serializer):
    """
    A user serializer for login.
    """
    email = serializers.CharField(max_length=300, required=True)
    password = serializers.CharField(required=True, write_only=True)

    @staticmethod
    def to_string_response_examples():
        return {
            'application/json': [
                'Invalid username/password. Please try again!'
            ],
        }


class AuthUserSerializer(serializers.ModelSerializer):
    """
    A user serializer for auth the user.
    """
    token = serializers.SerializerMethodField()
    social_name = serializers.SerializerMethodField()

    class Meta:
        model = LocalUser
        fields = (
            'id',
            'email',
            'email_confirmed',
            'is_social_auth',
            'social_name',
            'token',
        )
        read_only_fields = (
            'id',
            'email',
            'is_social_auth',
            'token',
        )

    def get_token(self, obj):
        token, _ = Token.objects.get_or_create(user=obj)
        return token.key

    def get_social_name(self, obj):
        profile = Profile.objects.get(user_id=obj.id)
        if profile:
            return profile.social_name
        return ''

    @staticmethod
    def to_string_response_examples():
        return {
            'application/json': {
                'id': 100,
                'email': 'user@email',
                'email_confirmed': False,
                'is_social_auth': False,
                'social_name': 'Name for social.',
            }
        }


class ResetPasswordSerializer(serializers.Serializer):
    """
    A user serialize for resetting password.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    reenter_new_password = serializers.CharField(required=True)

    def validate_old_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError('Old password does not match')
        return value

    def validate_new_password(self, value):
        password_validation.validate_password(value)
        return value

    def validate(self, attrs):
        if attrs.get('reenter_new_password') != attrs.get('new_password'):
            raise serializers.ValidationError({
                'reenter_new_password': 'The two password fields did not match.'
            })
        # Drop the unnecessary key for creating.
        attrs.pop('reenter_new_password')
        return attrs

    @staticmethod
    def to_string_response_examples():
        return {
            'application/json': {
                'old_password': ['Old password does not match',],
                'new_password': [
                    'This password is too short. It must contain at least 8 characters.',
                    'The password must contain at least 1 digit, 0-9.',
                    'The password must contain at least 1 uppercase letter, A-Z.',
                    'The password must contain at least 1 lowercase letter, a-z.',
                    'The password must contain at least 1 symbol',
                ],
                'reenter_new_password': [
                    'The two password fields did not match.',
                ]
            }
        }


class UpdateProfileSerializer(serializers.Serializer):
    """
    A user serialize for updating profile name.
    """
    social_name = serializers.CharField(max_length=150, required=True)


class UserListSerializer(serializers.ModelSerializer):
    """
    A user serialize for list about user detail.
    """

    class Meta:
        model = LocalUser
        fields = (
            'email',
            'date_joined',
            'login_count',
            'last_login',
        )
