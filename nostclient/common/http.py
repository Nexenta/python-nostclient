# Copyright 2012 Nexenta Systems Inc.

from urlparse import urlparse

try:
    from eventlet.green.httplib import HTTPException, \
        HTTPSConnection as BaseHTTPSConnection,\
        HTTPConnection as BaseHTTPConnection,\
        HTTPResponse as BaseHTTPResponse, CONTINUE, HTTPMessage
except ImportError:
    from httplib import HTTPException, \
        HTTPSConnection as BaseHTTPSConnection, \
        HTTPConnection as BaseHTTPConnection,\
        HTTPResponse as BaseHTTPResponse, CONTINUE, HTTPMessage

from nostclient.common.exceptions import ConnectionException


class BufferedHTTPResponse(BaseHTTPResponse):
    """HTTPResponse class that buffers reading of headers"""

    def __init__(self, sock, debuglevel=0, strict=0, method=None):
        self.sock = sock
        self.fp = sock.makefile('rb')
        self.debuglevel = debuglevel
        self.strict = strict
        self._method = method
        self.msg = None
        self.status = None
        self.version = None
        self.reason = None

    def expect_response(self):
        if self.fp:
            self.fp.close()
            self.fp = None
        self.fp = self.sock.makefile('rb', 0)
        version, status, reason = self._read_status()
        if status != CONTINUE:
            self._read_status = lambda: (version, status, reason)
            self.begin()
        else:
            self.status = status
            self.reason = reason.strip()
            self.version = 11
            self.msg = HTTPMessage(self.fp, 0)
            self.msg.fp = None

    def close(self):
        BaseHTTPResponse.close(self)
        self.sock = None


class HTTPConnection(BaseHTTPConnection):

    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=0):
        self._method = method  # save method for getexpect method
        return BaseHTTPConnection.putrequest(self, method, url, skip_host,
                                             skip_accept_encoding)

    def getexpect(self):
        response = BufferedHTTPResponse(self.sock, strict=self.strict,
                                        method=self._method)
        response.expect_response()
        return response


class HTTPSConnection(BaseHTTPSConnection):

    def putrequest(self, method, url, skip_host=0, skip_accept_encoding=0):
        self._method = method  # save method for getexpect method
        return BaseHTTPSConnection.putrequest(self, method, url, skip_host,
                                              skip_accept_encoding)

    def getexpect(self):
        response = BufferedHTTPResponse(self.sock, strict=self.strict,
                                        method=self._method)
        response.expect_response()
        return response


def http_connection(url, proxy=None):
    """
    Make an HTTPConnection or HTTPSConnection, through proxy if it defined.

    :param url: url to connect to
    :param proxy: proxy to connect through, if any; None by default; str of the
                  format 'http://127.0.0.1:8888' to set one
    :return: tuple of (parsed url, connection object)
    :raises ClientException: Unable to handle protocol scheme
    """
    parsed = urlparse(url)
    proxy_parsed = urlparse(proxy) if proxy else None
    if parsed.scheme == 'http':
        conn = HTTPConnection((proxy_parsed if proxy else parsed).netloc)
    elif parsed.scheme == 'https':
        conn = HTTPSConnection((proxy_parsed if proxy else parsed).netloc)
    else:
        raise ConnectionException('Cannot handle protocol scheme %s for url '
                                  '%s' % (parsed.scheme, repr(url)))
    if proxy:
        if hasattr(conn, '_set_tunnel'):
            conn._set_tunnel(parsed.hostname, parsed.port)
        else:
            conn.set_tunnel(parsed.hostname, parsed.port)
    return parsed, conn


def is_informational(status):
    """
    Check if HTTP status code is informational.

    :param status: http status code
    :returns: True if status is successful, else False
    """
    return 100 <= status and status <= 199


def is_success(status):
    """
    Check if HTTP status code is successful.

    :param status: http status code
    :returns: True if status is successful, else False
    """
    return 200 <= status and status <= 299


def is_redirection(status):
    """
    Check if HTTP status code is redirection.

    :param status: http status code
    :returns: True if status is redirection, else False
    """
    return 300 <= status and status <= 399


def is_client_error(status):
    """
    Check if HTTP status code is client error.

    :param status: http status code
    :returns: True if status is client error, else False
    """
    return 400 <= status and status <= 499


def is_server_error(status):
    """
    Check if HTTP status code is server error.

    :param status: http status code
    :returns: True if status is server error, else False
    """
    return 500 <= status and status <= 599


# List of HTTP status codes

###############################################################################
## 1xx Informational
###############################################################################

HTTP_CONTINUE = 100
HTTP_SWITCHING_PROTOCOLS = 101
HTTP_PROCESSING = 102  # WebDAV
HTTP_CHECKPOINT = 103
HTTP_REQUEST_URI_TOO_LONG = 122

###############################################################################
## 2xx Success
###############################################################################

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_ACCEPTED = 202
HTTP_NON_AUTHORITATIVE_INFORMATION = 203
HTTP_NO_CONTENT = 204
HTTP_RESET_CONTENT = 205
HTTP_PARTIAL_CONTENT = 206
HTTP_MULTI_STATUS = 207  # WebDAV
HTTP_IM_USED = 226

###############################################################################
## 3xx Redirection
###############################################################################

HTTP_MULTIPLE_CHOICES = 300
HTTP_MOVED_PERMANENTLY = 301
HTTP_FOUND = 302
HTTP_SEE_OTHER = 303
HTTP_NOT_MODIFIED = 304
HTTP_USE_PROXY = 305
HTTP_SWITCH_PROXY = 306
HTTP_TEMPORARY_REDIRECT = 307
HTTP_RESUME_INCOMPLETE = 308

###############################################################################
## 4xx Client Error
###############################################################################

HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_PAYMENT_REQUIRED = 402
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_METHOD_NOT_ALLOWED = 405
HTTP_NOT_ACCEPTABLE = 406
HTTP_PROXY_AUTHENTICATION_REQUIRED = 407
HTTP_REQUEST_TIMEOUT = 408
HTTP_CONFLICT = 409
HTTP_GONE = 410
HTTP_LENGTH_REQUIRED = 411
HTTP_PRECONDITION_FAILED = 412
HTTP_REQUEST_ENTITY_TOO_LARGE = 413
HTTP_REQUEST_URI_TOO_LONG = 414
HTTP_UNSUPPORTED_MEDIA_TYPE = 415
HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416
HTTP_EXPECTATION_FAILED = 417
HTTP_IM_A_TEAPOT = 418
HTTP_UNPROCESSABLE_ENTITY = 422  # WebDAV
HTTP_LOCKED = 423  # WebDAV
HTTP_FAILED_DEPENDENCY = 424  # WebDAV
HTTP_UNORDERED_COLLECTION = 425
HTTP_UPGRADE_REQUIED = 426
HTTP_PRECONDITION_REQUIRED = 428
HTTP_TOO_MANY_REQUESTS = 429
HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431
HTTP_NO_RESPONSE = 444
HTTP_RETRY_WITH = 449
HTTP_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450
HTTP_CLIENT_CLOSED_REQUEST = 499

###############################################################################
## 5xx Server Error
###############################################################################

HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_NOT_IMPLEMENTED = 501
HTTP_BAD_GATEWAY = 502
HTTP_SERVICE_UNAVAILABLE = 503
HTTP_GATEWAY_TIMEOUT = 504
HTTP_VERSION_NOT_SUPPORTED = 505
HTTP_VARIANT_ALSO_NEGOTIATES = 506
HTTP_INSUFFICIENT_STORAGE = 507  # WebDAV
HTTP_BANDWIDTH_LIMIT_EXCEEDED = 509
HTTP_NOT_EXTENDED = 510
HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511
HTTP_NETWORK_READ_TIMEOUT_ERROR = 598     # not used in RFC
HTTP_NETWORK_CONNECT_TIMEOUT_ERROR = 599  # not used in RFC
