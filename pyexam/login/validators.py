"""The validator used for password checking.

Used in settings.AUTH_PASSWORD_VALIDATORS
"""
import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class NumberValidator:
    """
    Validator that ensure password with at least one digit.
    """
    msg = 'The password must contain at least 1 digit, 0-9.'

    def validate(self, password, user=None):
        """Validate the password.

        Args:
            password: The user password that need to validate.

        Raises:
            ValidationError: If the password without digits.
        """
        del user
        if not re.findall('[0-9]', password):
            raise ValidationError(_(self.msg), code='password_no_number',)

    def get_help_text(self):
        """The help text with translation.
        """
        return _(self.msg)


class UppercaseValidator:
    """
    Validator that ensure password with at least one uppercase letter.
    """
    msg = 'The password must contain at least 1 uppercase letter, A-Z.'

    def validate(self, password, user=None):
        """Validate the password.

        Args:
            password: The user password that need to validate.

        Raises:
            ValidationError: If the password without uppercase letter.
        """
        del user
        if not re.findall('[A-Z]', password):
            raise ValidationError(_(self.msg), code='password_no_upper',)

    def get_help_text(self):
        """The help text with translation.
        """
        return _(self.msg)


class LowercaseValidator:
    """
    Validator that ensure password with at least one lowercase letter.
    """
    msg = 'The password must contain at least 1 lowercase letter, a-z.'

    def validate(self, password, user=None):
        """Validate the password.

        Args:
            password: The user password that need to validate.

        Raises:
            ValidationError: If the password without lowercase letter.
        """
        del user
        if not re.findall('[a-z]', password):
            raise ValidationError(_(self.msg), code='password_no_lower',)

    def get_help_text(self):
        """The help text with translation.
        """
        return _(self.msg)


class SymbolValidator:
    """
    Validator that ensure password with at least one symbol.
    """
    symbol = '[()[]{}|\\`~!@#$%^&*_-+=;:\'",<>./?]'
    msg = f'The password must contain at least 1 symbol:{symbol}'

    def validate(self, password, user=None):
        """Validate the password.

        Args:
            password: The user password that need to validate.

        Raises:
            ValidationError: If the password without symbol.
        """
        del user
        if not re.findall(self.symbol, password):
            raise ValidationError(_(self.msg), code='password_no_symbol',)

    def get_help_text(self):
        """The help text with translation.
        """
        return _(self.msg)
