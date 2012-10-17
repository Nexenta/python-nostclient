# Copyright 2012 Nexenta Systems Inc.


class CSClientException(Exception):
    """ Base class for all csclient exceptions """
    pass


class OptionError(CSClientException):
    """ Exception in command line options """
    pass


class ValidationError(CSClientException):
    """ Base class for validation error exceptions """
    pass


class ConnectionException(CSClientException):
    """ Exception during connection to sever """
    pass


class AuthorizationError(CSClientException):
    """ Exception during authorization request """
    pass


class ServiceError(CSClientException):
    """ Error on server side """

    def __init__(self, status=None, response=None, msg=None):
        self.status = status
        self.response = response
        self.msg = msg

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        out = []
        if self.msg:
            out.append(self.msg)
        if self.status and self.response:
            out.append("ERROR:(%s): %s" % (self.status, self.response.strip()))
        return '\n'.join(out)
