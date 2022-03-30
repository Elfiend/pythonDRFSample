from django.contrib.auth import authenticate, get_user_model

from rest_framework import serializers


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
            "Invalid username/password. Please try again!")
    return user
