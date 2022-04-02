from django.contrib.auth import authenticate, get_user_model

from rest_framework import serializers

from .models import Profile


def update_social_name(backend, user, response, *args, **kwargs):
    """
    Used to set social name after social account login.
    Called from .settings.SOCIAL_AUTH_PIPELINE

    Args:
        user(:obj: get_user_model) : The login user object.
    """
    del backend, response, args

    if not user:
        return
    profile = user.profile
    if profile is None:
        profile = Profile(user_id=user.id)
    if not profile.social_name:
        profile.social_name = kwargs.get('details').get('fullname')
        profile.save()


def create_user_account(email, password):
    """
    Used to create account with email.
    """
    user = get_user_model().objects.create_user(email=email, password=password)
    return user


def get_and_authenticate_user(email, password):
    """
    Used to authenticate the user.
    """
    user = authenticate(username=email, password=password)
    if user is None:
        raise serializers.ValidationError(
            'Invalid username/password. Please try again!')
    return user
