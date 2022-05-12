"""
Provides the custom permission policies.
"""
from rest_framework import permissions


class IsEmailConfirmed(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_permission(self, request, view):
        return request.user.email_confirmed
