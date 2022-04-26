import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class NumberValidator(object):
    msg = 'The password must contain at least 1 digit, 0-9.'

    def validate(self, password, user=None):
        if not re.findall('\d', password):
            raise ValidationError(_(self.msg), code='password_no_number',)

    def get_help_text(self):
        return _(self.msg)


class UppercaseValidator(object):
    msg = 'The password must contain at least 1 uppercase letter, A-Z.'

    def validate(self, password, user=None):
        if not re.findall('[A-Z]', password):
            raise ValidationError(_(self.msg), code='password_no_upper',)

    def get_help_text(self):
        return _(self.msg)


class LowercaseValidator(object):
    msg = 'The password must contain at least 1 lowercase letter, a-z.'

    def validate(self, password, user=None):
        if not re.findall('[a-z]', password):
            raise ValidationError(_(self.msg), code='password_no_lower',)

    def get_help_text(self):
        return _(self.msg)


class SymbolValidator(object):
    symbol = '[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]'
    msg = f'The password must contain at least 1 symbol:{symbol}'

    def validate(self, password, user=None):
        if not re.findall(self.symbol, password):
            raise ValidationError(_(self.msg), code='password_no_symbol',)

    def get_help_text(self):
        return _(self.msg)
