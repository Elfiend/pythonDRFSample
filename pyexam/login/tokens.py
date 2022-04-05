"""
Used to create token by my way.
"""
from django.contrib.auth.tokens import PasswordResetTokenGenerator

import six


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    """
    Rewrite the way to produce a token.
    Avoid invalidated while password changed or last_login updated.
    """

    def _make_hash_value(self, user, timestamp):
        return (six.text_type(user.pk) + six.text_type(timestamp) +
                six.text_type(user.email_confirmed))


account_activation_token = AccountActivationTokenGenerator()
