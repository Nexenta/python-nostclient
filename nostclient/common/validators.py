# Copyright 2012 Nexenta Systems Inc.

from urlparse import urlparse

from nostclient.common.constants import EMPTY_VALUES
from nostclient.common.exceptions import ValidationError


class Validator(object):

    def __init__(self, message='Validation error'):
        self.message = message


class NotEmptyValidator(Validator):

    def __call__(self, value):
        if value in EMPTY_VALUES:
            raise ValidationError(self.message)
        return value


class NotUrlValidator(Validator):

    def __call__(self, value):
        valid_value = urlparse(value)
        if valid_value.scheme not in ('http', 'https'):
            raise ValidationError(self.message)
        return value
