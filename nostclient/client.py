# Copyright 2012 Nexenta Systems Inc.

from __future__ import with_statement

import os
import sys
from time import sleep
from threading import Thread
from Queue import Empty, Queue
from hashlib import sha256, md5
from urlparse import urlparse, urljoin
from urllib import unquote, quote as ulquote

try:
    import simplejson as json
except ImportError:
    import json

from nostclient.common.constants import DISK_CHUNK_SIZE, NETWORK_CHUNK_SIZE,\
    ACP_VALUES, MiB
from nostclient.common.http import http_connection, is_success, \
    HTTP_UNAUTHORIZED, HTTP_NO_CONTENT, HTTP_CONTINUE
from nostclient.common.exceptions import ServiceError, AuthorizationError


def quote(value, safe='/'):
    """
    Patched version of urllib.quote that encodes utf8 strings before quoting
    """
    if isinstance(value, unicode):
        value = value.encode('utf8')
    return ulquote(value, safe)


def json_request(method, url, **kwargs):
    """Parse a request in json and return in json"""
    kwargs.setdefault('headers', {})
    if 'body' in kwargs:
        kwargs['headers']['Content-Type'] = 'application/json'
        kwargs['body'] = json.dumps(kwargs['body'])
    purl, conn = http_connection(url)
    conn.request(method, purl.path, **kwargs)
    resp = conn.getresponse()
    if not is_success(resp.status):
        raise ServiceError(resp.status, resp.read())
    body = resp.read()
    if body:
        try:
            body = json.loads(body)
        except ValueError:
            body = None
    if not body:
        raise ServiceError(resp.status, body)
    return resp, body


def lower_headers(headers):
    """ Change register of all headers key to lower """
    return dict((header.lower(), value) for header, value in headers)


class QueueFunctionThread(Thread):

    def __init__(self, queue, func, client, req_url=None, req_auth_token=None):
        super(QueueFunctionThread, self).__init__()
        self.abort = False
        self.queue = queue
        self.func = func
        self.client = client
        self.http_conn = None
        self.req_url = req_url
        self.req_auth_token = req_auth_token
        self.exc_infos = []

    def run(self):
        conn, path, url, auth_token = \
            self.client.validate_conn(self.http_conn, self.req_url,
                                      self.req_auth_token)
        kwargs = {'http_conn': conn, 'req_url': url,
                  'req_auth_token': auth_token}
        while True:
            try:
                args = self.queue.get_nowait()
            except Empty:
                if self.abort:
                    break
                sleep(0.01)
            else:
                try:
                    if not self.abort:
                        self.func(*args, **kwargs)
                except Exception, e:
                    self.exc_infos.append(sys.exc_info())
                finally:
                    self.queue.task_done()


class ChunkGenerator(object):

    def __init__(self, client, container, object, manifest, etag,
                 content_length, http_conn=None, req_url=None,
                 req_auth_token=None, network_chunk_size=NETWORK_CHUNK_SIZE):
        self.client = client
        self.container = container
        self.object = object
        self.manifest = manifest
        self.etag = etag
        self.content_length = int(content_length)
        self.network_chunk_size = network_chunk_size
        self.http_conn = http_conn
        self.req_url = req_url
        self.req_auth_token = req_auth_token
        self.chunks = self.manifest.get('chunks', [])
        self.chunks = sorted(self.chunks, key=lambda c: c.get('offset'))

    def next(self):
        return iter(self).next()

    def save(self, filename, threads_count=5, callback=None):
        if callback is None:
            callback = lambda *args: None
        chunk_queue = Queue(10000)

        def _download_chunk(client, container, obj, filename, chunk, offset,
                            network_chunk_size, callback):
            status, headers, resp = client.get_chunk(container, obj, chunk)
            etag = headers['etag']
            md5sum = md5()
            total = 0
            with open(filename, 'ab') as fdp:
                fd = fdp.fileno()
                if offset:
                    os.lseek(fd, offset, os.SEEK_SET)
                buf = resp.read(network_chunk_size)
                while buf:
                    os.write(fd, buf)
                    md5sum.update(buf)
                    callback(len(buf))
                    total += len(buf)
                    buf = resp.read(network_chunk_size)
                del buf
            md5sum = md5sum.hexdigest()
            if md5sum != etag:
                raise ValueError('%s: md5sum != etag; %s != %s' %
                                 (chunk, md5sum, etag))

        chunk_threads = [QueueFunctionThread(chunk_queue, _download_chunk)
                         for i in xrange(threads_count)]
        for thread in chunk_threads:
            thread.start()
        offset = 0
        for chunk in self.chunks:
            if 'offset' in chunk:
                offset = chunk['offset']
            open(filename, 'wb').close()
            chunk_queue.put((self.client, self.container, self.object,
                             filename, chunk['hash'], offset,
                             self.network_chunk_size, callback))
            offset += chunk['size']
        while not chunk_queue.empty():
            sleep(0.01)
        for thread in chunk_threads:
            thread.abort = True
            while thread.isAlive():
                thread.join(0.01)

    def __iter__(self):
        conn, path, url, auth_token =\
            self.client.validate_conn(self.http_conn, self.req_url,
                                      self.req_auth_token)
        for chunk in self.chunks:
            resp = self.client.get_chunk(
                self.container, self.object, chunk['hash'],
                http_conn=conn, req_url=url, req_auth_token=auth_token)[2]
            for block in resp:
                yield block


class NSclient(object):

    def __init__(self, auth_url=None, auth_version=None, user=None, key=None,
                 proxy_host=None, proxy_port=None, proxy_user=None,
                 proxy_pass=None, disk_chunk_size=DISK_CHUNK_SIZE,
                 network_chunk_size=NETWORK_CHUNK_SIZE, debug=False,
                 http_connection_factory=http_connection):
        self.auth_url = auth_url
        self.auth_version = auth_version
        self.user = user
        self.key = key
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_pass = proxy_pass
        self.disk_chunk_size = disk_chunk_size
        self.network_chunk_size = network_chunk_size
        self.debug = debug
        self.http_connection_factory = http_connection_factory

    def validate_conn(self, conn=None, storage_url=None, auth_token=None):
        """
        Validate connection and authorization parameters if its presented, else
        returns new connection object and authorization parameters.

        :param conn: connection object
        :param storage_url: storage URL
        :param auth_token: authorization token
        :return: tuple of (connection object, storage url path, storage url,
                 authorization token)
        """
        if not storage_url or not auth_token:
            storage_url, auth_token = self.auth_request()
        if not conn:
            purl, conn = self.http_connection_factory(storage_url)
        else:
            purl = urlparse(storage_url)
        return conn, purl.path, storage_url, auth_token

    def auth_request_v1(self):
        purl, conn = http_connection(self.auth_url)
        url = purl.path
        headers = {'X-Auth-User': self.user, 'X-Auth-Key': self.key}
        conn.request('GET', url, '', headers)
        resp = conn.getresponse()
        if not is_success(resp.status):
            if resp.status == HTTP_UNAUTHORIZED:
                raise AuthorizationError('Authorization error')
            raise ServiceError(resp.status, resp.read(), 'Authorization error')
        storage_url = unquote(resp.getheader('x-storage-url'))
        auth_token = resp.getheader('x-auth-token')
        return storage_url, auth_token

    def auth_request_v2(self, tenant_name, region):
        if not tenant_name and ':' in self.user:
            tenant_name, user = self.user.split(':', 1)
        else:
            user = self.user
        purl, conn = http_connection(self.auth_url)
        url = purl.path
        body = {
            'tenantName': tenant_name,
            'auth': {
                'passwordCredentials': {
                    'password': self.key,
                    'username': user
                }
            }
        }
        token_url = urljoin(url, 'tokens')
        resp, body = json_request('POST', token_url, body=body)
        token_id = None
        try:
            url = None
            catalogs = body['access']['serviceCatalog']
            for service in catalogs:
                if service['type'] == 'object-store':
                    endpoints = service['endpoints']
                    if region:
                        for endpoint in endpoints:
                            if endpoint['region'] == region:
                                url = endpoint['publicURL']
                        if not url:
                            raise ServiceError(resp.status, body,
                                               'There is no object-store '
                                               'endpoint for region %s.' %
                                               region)
                    else:
                        url = endpoints[0]['publicURL']
            token_id = body['access']['token']['id']
            if not url:
                raise ServiceError(resp.status, body, 'There is no '
                                   'object-store endpoint on this auth server')
        except (KeyError, IndexError):
            raise AuthorizationError('Authorization error')
        return url, token_id

    def auth_request(self, tenant_name=None, region=''):
        if self.auth_version == '1.0':
            return self.auth_request_v1()
        elif self.auth_version == '2.0':
            return self.auth_request_v2(tenant_name, region)

    def put_account(self, headers=None, http_conn=None, req_url=None,
                    req_auth_token=None):
        """
        Creates an account.

        :param headers: additional headers to include in the request
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: None if account created
        :raises ServiceError: if container PUT failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        heads = headers or {}
        heads['X-Auth-Token'] = auth_token
        conn.request('PUT', path, '', heads)
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               'Account: PUT failed')

    def put_container(self, container, headers=None, http_conn=None,
                      req_url=None, req_auth_token=None):
        """
        Creates a container

        :param container: container name to create
        :param headers: additional headers to include in the request
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: None if container created
        :raises ServiceError: if container PUT failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s' % (path, quote(container))
        heads = headers or {}
        heads['X-Auth-Token'] = auth_token
        heads['X-Container-Type'] = 'ccow'
        conn.request('PUT', path, '', heads)
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               'Container %s: PUT failed' % container)

    def put_placeholder(self, container, manifest, headers=None,
                        http_conn=None, req_url=None, req_auth_token=None):
        """
        Creates the manifest placeholder.

        :param container: container name to create manifest
        :param manifest: manifest name to create
        :param headers: additional headers to include in the request
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token
        :return: a tuple of session id and session timestamp
        :raises ServiceError: if manifest placeholder PUT failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s/%s' % (path.rstrip('/'), quote(container),
                             quote(manifest))
        heads = headers or {}
        if heads:
            heads = heads.copy()
        heads['X-Auth-Token'] = auth_token
        heads['X-Oneput-Manifest'] = 'true'
        heads['Content-Length'] = '0'
        conn.request('PUT', path, '', heads)
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               'Manifest placeholder %s/%s: PUT failed' %
                               (container, manifest))
        resp_headers = lower_headers(response.getheaders())
        session_id = resp_headers['x-session-id']
        session_timestamp = resp_headers['x-session-timestamp']
        return session_id, session_timestamp

    def put_manifest(self, container, manifest, content,
                     object_content_length, object_etag, session_id,
                     session_timestamp, object_content_type=None, headers=None,
                     http_conn=None, req_url=None, req_auth_token=None):
        """
        Creates the manifest.

        :param container: container name
        :param manifest: manifest name
        :param content: a manifest dict
        :param object_content_length: value to send as x-object-content-length
                                      header
        :param object_etag: value to send as x-object-etag header
        :param session_id: session id
        :param session_timestamp: session timestamp
        :param object_content_type: value to send as x-object-content-type
                                    header; if None, no content-type will be
                                    set (remote end will likely try to
                                    auto-detect it)
        :param headers: additional headers to include in the request
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token
        :return: None if manifest created
        :raises ServiceError: if manifest PUT failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s/%s' % (path.rstrip('/'), quote(container),
                             quote(manifest))
        heads = headers or {}
        if heads:
            heads = heads.copy()
        data = json.dumps(content)
        heads['X-Auth-Token'] = auth_token
        heads['X-Oneput-Manifest'] = 'true'
        heads['X-Only-Manifest'] = 'true'
        heads['Content-Type'] = 'application/json'
        heads['Content-Length'] = len(data)
        heads['ETag'] = md5(data).hexdigest()
        heads['X-Session-Id'] = session_id
        heads['X-Session-Timestamp'] = session_timestamp
        heads['X-Object-Content-Length'] = object_content_length
        heads['X-Object-ETag'] = object_etag
        if object_content_type:
            heads['X-Object-Content-Type'] = object_content_type
        conn.request('PUT', path, data, heads)
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               'Manifest %s/%s: PUT failed' %
                               (container, manifest))

    def put_chunk(self, container, manifest, content, session_id,
                  session_timestamp, headers=None, http_conn=None,
                  req_url=None, req_auth_token=None, callback=None):
        """
        Creates the chunk.

        :param container: container name to create chunk
        :param manifest: manifest name to create chunk
        :param content: string or a file like object to read object data from
        :param session_id: session id
        :param session_timestamp: session timestamp
        :param headers: additional headers to include in the request
        :param http_conn: HTTP connection object (If None, it will be created
                          the conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token
        :param callback: callback function for update already upload chunk
                         bytes

        :return: tuple of chunk fingerprint and chunk size
        :raises ServiceError: if chunk PUT failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        if hasattr(content, 'read'):
            content = content.read()
        etag = md5(content).hexdigest()
        id = sha256(content).hexdigest()
        content_length = len(content)
        path = '/chunk/%s/%s/%s/%s' % (path.strip('/'), quote(container),
                                       quote(manifest), quote(id))
        heads = headers or {}
        if heads:
            heads = heads.copy()
        heads['X-Only-Manifest'] = 'true'
        heads['X-Auth-Token'] = auth_token
        heads['Etag'] = etag
        heads['Content-Type'] = 'application/octet-stream'
        heads['Content-Length'] = content_length
        heads['X-Session-Id'] = session_id
        heads['X-Session-Timestamp'] = session_timestamp
        heads['Connection'] = 'close'
        heads['Expect'] = '100-continue'
        conn.putrequest('PUT', path)
        for header, value in heads.iteritems():
            conn.putheader(header, value)
        conn.endheaders()
        resp = conn.getexpect()
        if resp.status != HTTP_CONTINUE:
            if callback:
                callback(content_length)
        else:
            resp.close()
            while content:
                buf = content[:self.network_chunk_size]
                content = content[self.network_chunk_size:]
                conn.send(buf)
                if callback:
                    callback(len(buf))
                del buf
            resp = conn.getresponse()
        if not is_success(resp.status):
            raise ServiceError(resp.status, resp.read(),
                               'Chunk %s/%s/%s: PUT failed' %
                               (container, manifest, id))
        resp_headers = lower_headers(resp.getheaders())
        if etag != resp_headers['etag']:
            raise ServiceError(resp.status, resp.read(),
                               'Chunk %s/%s/%s: PUT failed request and '
                               'response etag are not equal' %
                               (container, manifest, id))
        return id, content_length

    def put_directory(self, container, manifest, headers=None, http_conn=None,
                      req_url=None, req_auth_token=None):
        """
        Creates the directory.

        :param container: container name to create manifest
        :param manifest: directory name to create
        :param headers: additional headers to include in the request
        :param http_conn: HTTP connection object (If None, it will be created
                          the conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: None if directory was created
        :raises ServiceError: if manifest PUT failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        id, timestamp = self.put_placeholder(container, manifest,
                                             http_conn=conn, req_url=url,
                                             req_auth_token=auth_token)
        content = {'chunks': []}
        etag = md5('').hexdigest()
        self.put_manifest(container, manifest, content, '0', etag, id,
                          timestamp, 'text/directory', headers,
                          req_url=url, req_auth_token=auth_token)

    def put_object(self, container, obj, contents, content_type=None,
                   headers=None, http_conn=None, req_url=None,
                   req_auth_token=None, chunk_size=MiB, callback=None,
                   error_callback=None, workers=5):
        """
        Puts an object

        :param container: container name
        :param obj: object name
        :param contents: a string or a file like object to read data from
        :param content_type: value to send as content-type header; if None, no
                             content-type will be set (remote end will likely
                             try to auto-detect it)
        :param headers: additional headers to include in the request, if any
        :param http_conn: HTTP connection object (If None, it will be created
                          the conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token
        :param chunk_size: chunk size of data to read; default 1024 * 1024
        :param callback: callback function, that will called after each chunk
                         uploaded
        :param error_callback: error callback function, that will called if
                               error occur
        :param workers: number of workers thread

        :return: object etag
        :raises ServiceError: object PUT request failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        session_id, session_timestamp =\
            self.put_placeholder(container, obj, http_conn=conn, req_url=url,
                                 req_auth_token=auth_token)
        etag = md5()
        content_length = 0
        workers_exceptions = []
        manifest = {'chunks': []}
        chunk_queue = None
        if workers != 1:
            chunk_queue = Queue(workers * 2)

        def _upload_chunk(buf, offset, http_conn=None, req_url=None,
                          req_auth_token=None):
            try:
                id, size = self.put_chunk(
                    container, obj, buf, session_id, session_timestamp,
                    http_conn=http_conn, req_url=req_url,
                    req_auth_token=req_auth_token, callback=callback)
                manifest['chunks'].append({'hash': id, 'size': size,
                                           'offset': offset})
            except Exception, e:
                workers_exceptions.append(e)

        if chunk_queue:
            chunk_threads = [
                QueueFunctionThread(chunk_queue, _upload_chunk, self,
                                    req_url=url, req_auth_token=auth_token)
                for i in xrange(workers)]
            for thread in chunk_threads:
                thread.start()
        try:
            if isinstance(contents, basestring):
                while contents:
                    buf = contents[:chunk_size]
                    contents = contents[chunk_size:]
                    if chunk_queue:
                        chunk_queue.put((buf, content_length))
                    else:
                        _upload_chunk(buf, content_length, req_url=url,
                                      req_auth_token=auth_token)
                    etag.update(buf)
                    content_length += len(buf)
            else:
                buf = ''
                reader = contents.read
                data_source = iter(lambda: reader(self.disk_chunk_size), '')
                eof = False
                while not eof:
                    try:
                        buf += next(data_source)
                    except StopIteration:
                        eof = True
                    while buf and ((len(buf) >= chunk_size) or eof):
                        buf, remainder = buf[:chunk_size], buf[chunk_size:]
                        chunk_queue.put((buf, content_length))
                        etag.update(buf)
                        content_length += len(buf)
                        buf = remainder
                    if workers_exceptions:
                        raise ServiceError(
                            msg='Exception in chunk upload thread')
            if chunk_queue:
                while not chunk_queue.empty():
                    sleep(0.01)
            if workers_exceptions:
                raise ServiceError(
                    msg='Exception in chunk upload thread')
        except (KeyboardInterrupt, Exception), e:
            if error_callback:
                error_callback()
            raise e
        finally:
            if chunk_queue:
                for thread in chunk_threads:
                    thread.abort = True
                    while thread.isAlive():
                        thread.join(0.01)

        etag = etag.hexdigest()
        self.put_manifest(container, obj, manifest, content_length, etag,
                          session_id, session_timestamp, content_type, headers,
                          req_url=url, req_auth_token=auth_token)
        return etag

    def stat_account(self, http_conn=None, req_url=None, req_auth_token=None):
        """
        Gets account stats.

        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), response object)
        :raises ServiceError: if account HEAD failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        conn.request('HEAD', path, '', {'X-Auth-Token': auth_token})
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               'Account HEAD failed')
        return response.status, lower_headers(response.getheaders()), response

    def stat_container(self, container, http_conn=None, req_url=None,
                       req_auth_token=None):
        """
        Gets container stats.

        :param container: container name to get a stats for
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), response object)
        :raises ServiceError: if container HEAD failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s' % (path, quote(container))
        conn.request('HEAD', path, '', {'X-Auth-Token': auth_token})
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               'Container %s: HEAD failed' % container)
        return response.status, lower_headers(response.getheaders()), response

    def stat_manifest(self, container, manifest, version_id=None,
                      http_conn=None, req_url=None, req_auth_token=None):
        """
        Gets manifest stats.

        :param container: container name to get a stats for
        :param manifest: manifest name to get a stats for
        :param version_id: manifest version id
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), response object)
        :raises ServiceError: if manifest HEAD failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s/%s' % (path, quote(container), quote(manifest))
        query = ''
        if version_id:
            query = '?versionId=%s' % quote(version_id)
        headers = {'X-Auth-Token': auth_token, 'X-Oneput-Manifest': 'true'}
        conn.request('HEAD', path + query, '', headers)
        response = conn.getresponse()
        if not is_success(response.status):
            name = '%s/%s' % (container, manifest)
            if version_id:
                name += ' version id %s' % version_id
            raise ServiceError(response.status, response.read(),
                               'Manifest %s: HEAD failed' % name)
        return response.status, lower_headers(response.getheaders()), response

    def get_account(self, marker=None, end_marker=None, limit=None,
                    prefix=None, delimiter=None, full_listing=False,
                    http_conn=None, req_url=None, req_auth_token=None):
        """
        Shows a listing of containers for the account.

        :param marker: marker query
        :param end_marker: end marker query
        :param limit: limit query
        :param prefix: prefix query
        :param delimiter: delimiter query
        :param full_listing: if True, return a full listing, else returns a max
                             of 10000 listings
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), a list of containers)
        :raises ServiceError: if account GET failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        if full_listing:
            rv = self.get_account(marker, end_marker, limit, prefix, delimiter,
                                  False, http_conn=conn, req_url=url,
                                  req_auth_token=auth_token)
            listing = rv[2]
            while listing:
                marker = listing[-1]['name']
                listing = self.get_account(
                    marker, end_marker, limit, prefix, delimiter, False,
                    http_conn=conn, req_url=url, req_auth_token=auth_token)[2]
                if listing:
                    rv[2].extend(listing)
            return rv
        query = 'format=json'
        if marker:
            query += '&marker=%s' % quote(marker)
        if end_marker:
            query += '&end_marker=%s' % quote(end_marker)
        if limit:
            query += '&limit=%d' % limit
        if prefix:
            query += '&prefix=%s' % quote(prefix)
        headers = {'X-Auth-Token': auth_token}
        conn.request('GET', '%s?%s' % (path, query), '', headers)
        resp = conn.getresponse()
        if not is_success(resp.status):
            raise ServiceError(resp.status, resp.read(), 'Account GET failed')
        resp_headers = lower_headers(resp.getheaders())
        if resp.status == HTTP_NO_CONTENT:
            return resp.status, resp_headers, []
        return resp.status, resp_headers, json.loads(resp.read())

    def get_container(self, container, marker=None, end_marker=None,
                      limit=None, prefix=None, delimiter=None,
                      full_listing=False, http_conn=None, req_url=None,
                      req_auth_token=None):
        """
        Shows a listing of objects for the container.

        :param container: container name to get a listing for
        :param marker: marker query
        :param end_marker: end_marker query
        :param limit: limit query
        :param prefix: prefix query
        :param delimiter: string to delimit the queries on
        :param full_listing: if True, return a full listing, else returns a max
                             of 10000 listings
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), a list of manifests)
        :raises ServiceError: if container GET failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        if full_listing:
            rv = self.get_container(container, marker, end_marker, limit,
                                    prefix, delimiter, False, http_conn=conn,
                                    req_url=url, req_auth_token=auth_token)[2]
            listing = rv[2]
            while listing:
                if not delimiter:
                    marker = listing[-1]['name']
                else:
                    marker = listing[-1].get('name', listing[-1].get('subdir'))
                listing = self.get_container(container, marker, end_marker,
                                             limit, prefix, delimiter, False,
                                             http_conn=conn, req_url=url,
                                             req_auth_token=auth_token)[2]
                if listing:
                    rv[2].extend(listing)
            return rv
        path = '%s/%s' % (path, quote(container))
        query = 'format=json'
        if marker:
            query += '&marker=%s' % quote(marker)
        if end_marker:
            query += '&end_marker=%s' % quote(end_marker)
        if limit:
            query += '&limit=%d' % int(limit)
        if prefix:
            query += '&prefix=%s' % quote(prefix)
        if delimiter:
            query += '&delimiter=%s' % quote(delimiter)
        headers = {'X-Auth-Token': auth_token}
        conn.request('GET', '%s?%s' % (path, query), '', headers)
        resp = conn.getresponse()
        if not is_success(resp.status):
            raise ServiceError(resp.status, resp.read(),
                               'Container %s: GET failed' % container)
        resp_headers = lower_headers(resp.getheaders())
        data = []
        if resp.status != HTTP_NO_CONTENT:
            data = json.loads(resp.read())
        return resp.status, resp_headers, data

    def get_manifest(self, container, manifest, version_id=None,
                     http_conn=None, req_url=None, req_auth_token=None):
        """
        Shows a listing of chunks in the manifest.

        :param container: container name
        :param manifest: manifest name
        :param version_id: manifest version id
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), a dictionary of the manifest content)
        :raises ServiceError: if manifest GET failed or manifest invalid
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s/%s' % (path, quote(container), quote(manifest))
        headers = {'X-Auth-Token': auth_token, 'X-Oneput-Manifest': 'true'}
        query = '?format=json'
        if version_id:
            query += '&versionId=%s' % quote(version_id)
        conn.request('GET', path + query, '', headers)
        resp = conn.getresponse()
        if not is_success(resp.status):
            name = '%s/%s' % (container, manifest)
            if version_id:
                name += ' version id %s' % version_id
            raise ServiceError(resp.status, resp.read(),
                               'Manifest %s: GET failed' % name)
        resp_headers = lower_headers(resp.getheaders())
        manifest = {}
        if resp.status != HTTP_NO_CONTENT:
            manifest = json.loads(resp.read())
            for chunk in manifest.get('chunks', []):
                if not isinstance(chunk, dict):
                    raise ServiceError(
                        msg='Chunk in manifest chunks should be a dict')
                if 'hash' not in chunk:
                    raise ServiceError(msg='Each chunk should contain hash')
        return resp.status, resp_headers, manifest

    def get_chunk(self, container, manifest, chunk, http_conn=None,
                  req_url=None, req_auth_token=None):
        """
        Returns chunk content.

        :param container: container name
        :param manifest: manifest name
        :param chunk: chunk id
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), response object)
        :raises ServiceError: if chunk GET failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '/chunk%s/%s/%s/%s' % (path, quote(container), quote(manifest),
                                      chunk)
        headers = {'X-Auth-Key': auth_token}
        conn.request('GET', path, '', headers)
        resp = conn.getresponse()
        if not is_success(resp.status):
            name = '%s/%s/%s' % (container, manifest, chunk)
            raise ServiceError(resp.status, resp.read(),
                               'Chunk %s: GET failed' % name)
        chunk_body = iter(lambda: resp.read(self.network_chunk_size), '')
        return resp.status, lower_headers(resp.getheaders()), chunk_body

    def get_object(self, container, object, version_id=None, http_conn=None,
                   req_url=None, req_auth_token=None):
        """
        Gets object if it is without manifest.

        :param container: container name
        :param object: object name to get for
        :param version_id: object version id
        :param http_conn: HTTP connection object (If None, it will be created
                          the conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), generator object for object content)
        :raises ServiceError: if object GET failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        status, headers, manifest =\
            self.get_manifest(container, object, version_id=version_id,
                              http_conn=conn, req_url=url,
                              req_auth_token=auth_token)
        etag = headers.get('x-object-etag')
        content_length = headers.get('x-object-content-length')
        resp = ChunkGenerator(
            self, container, object, manifest, etag, content_length,
            http_conn=conn, req_url=url, req_auth_token=auth_token,
            network_chunk_size=self.network_chunk_size)
        return status, headers, resp

    def get_versions_list(self, container, marker=None, end_marker=None,
                          vmarker=None, end_vmarker=None, limit=None,
                          prefix=None, delimiter=None, full_listing=False,
                          http_conn=None, req_url=None, req_auth_token=None):
        """
        Shows a listing of object's versions in the container.

        :param container: container name
        :param marker: marker query
        :param end_marker: end_marker query
        :param vmarker: vmarker query
        :param end_vmarker: end_vmarker query
        :param limit: limit query
        :param prefix: prefix query
        :param delimiter: string to delimit the queries on
        :param full_listing: if True, return a full listing, else returns a max
                             of 10000 listings
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), a list of manifests versions)
        :raises ServiceError: if GET versions request failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        if full_listing:
            rv = self.get_versions_list(
                container, marker, end_marker, vmarker, end_vmarker, limit,
                prefix, delimiter, full_listing, req_url=url,
                req_auth_token=auth_token)
            listing = rv[2]
            while listing:
                if not delimiter:
                    marker = listing[-1]['name']
                else:
                    marker = listing[-1].get('name', listing[-1].get('subdir'))
                listing = self.get_versions_list(
                    container, marker, end_marker, vmarker, end_vmarker, limit,
                    prefix, delimiter, full_listing, req_url=url,
                    req_auth_token=auth_token)[2]
                if listing:
                    rv[2].extend(listing)
            return rv
        path = '%s/%s' % (path, quote(container))
        query = '?versions&format=json'
        if marker:
            query += '&marker=%s' % quote(marker)
        if end_marker:
            query += '&end_marker=%s' % quote(end_marker)
        if vmarker:
            query += '&vmarker=%s' % quote(vmarker)
        if end_vmarker:
            query += '&end_vmarker=%s' % quote(end_vmarker)
        if limit:
            query += '&limit=%d' % int(limit)
        if prefix:
            query += '&prefix=%s' % quote(prefix)
        if delimiter:
            query += '&delimiter=%s' % quote(delimiter)
        headers = {'X-Auth-Token': auth_token}
        conn.request('GET', path + query, '', headers)
        resp = conn.getresponse()
        if not is_success(resp.status):
            raise ServiceError(resp.status, resp.read(),
                               'Container %s: GET versions failed' % container)
        resp_headers = lower_headers(resp.getheaders())
        data = []
        if resp.status != HTTP_NO_CONTENT:
            data = json.loads(resp.read())
        return resp.status, resp_headers, data

    def get_versioning(self, container, http_conn=None, req_url=None,
                       req_auth_token=None):
        """
        Shows versioning status of the container.

        :param container: container name
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), response object, container versioning status)
        :raises ServiceError: if HEAD versioning request failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s' % (path, quote(container))
        conn.request('HEAD', path, '', {'X-Auth-Token': auth_token})
        resp = conn.getresponse()
        if not is_success(resp.status):
            raise ServiceError(resp.status, resp.read(),
                               'Container %s versioning HEAD failed' %
                               container)
        resp_headers = lower_headers(resp.getheaders())
        if 'x-container-versioning' not in resp_headers:
            raise ServiceError(
                msg='Container %s versioning header is not found' % container)
        versioning = resp_headers['x-container-versioning']
        return resp.status, resp_headers, resp, versioning

    def _get_acp(self, container, manifest=None, version_id=None,
                 http_conn=None, req_url=None, req_auth_token=None):
        """
        Shows ACL permissions for the container or manifest.

        :param container: container name
        :param manifest: manifest name
        :param version_id: version id of manifest if it presented
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all lowercase))
        :raises ServiceError: if ACL GET request failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        typ, name = 'Container', container
        path = '%s/%s' % (path, quote(container))
        query = 'acl&format=json'
        headers = {'X-Auth-Token': auth_token}
        if manifest:
            typ, name = 'Manifest', name + '/' + manifest
            path = '%s/%s' % (path, quote(manifest))
            headers['X-Oneput-Manifest'] = 'true'
            if version_id:
                name += ' version id %s' % version_id
                query += '&versionId=%s' % version_id
        conn.request('HEAD', '%s?%s' % (path, query), '', headers)
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               '%s %s: HEAD ACL failed' % (typ, name))
        return response.status, lower_headers(response.getheaders())

    def get_container_acp(self, container, http_conn=None, req_url=None,
                          req_auth_token=None):
        """
        Shows ACL permissions for the container.

        :param container: container name
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all lowercase))
        :raises ServiceError: if GET ACL request failed
        """
        return self._get_acp(container, http_conn=http_conn, req_url=req_url,
                             req_auth_token=req_auth_token)

    def get_manifest_acp(self, container, manifest, version_id=None,
                         http_conn=None, req_url=None, req_auth_token=None):
        """
        Shows ACL permissions for the manifest.

        :param container: container name
        :param manifest: manifest name
        :param version_id: manifest version id
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all lowercase))
        :raises ServiceError: if GET ACL request failed
        """
        return self._get_acp(container, manifest=manifest,
                             version_id=version_id, http_conn=http_conn,
                             req_url=req_url, req_auth_token=req_auth_token)

    def set_versioning(self, container, versioning, http_conn=None,
                       req_url=None, req_auth_token=None):
        """
        Sets versioning status for the container.

        :param container: container name
        :param versioning: wanted versioning status
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), response object)
        :raises ServiceError: versioning POST request failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s' % (path, quote(container))
        if versioning not in ('enabled', 'suspended'):
            raise ServiceError(
                msg='Invalid versioning status: %s' % versioning)
        headers = {'X-Auth-Token': auth_token,
                   'X-Container-Versioning': versioning}
        conn.request('POST', path, '', headers)
        resp = conn.getresponse()
        if not is_success(resp.status):
            raise ServiceError(resp.status, resp.read(),
                               'Container %s: POST versioning failed' %
                               container)
        return resp.status, lower_headers(resp.getheaders()), resp

    def _set_acp(self, acl, container, manifest=None, version_id=None,
                 http_conn=None, req_url=None, req_auth_token=None):
        """
        Sets ACL for container or manifest.

        :param acl: acl list
        :param container: container name
        :param manifest: manifest name
        :param version_id: version id of manifest if it presented
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), response object)
        :raises ServiceError: if POST ACL request failed
        """
        perm2users = {}
        for acp in acl:
            perms = acp['permissions']
            if isinstance(perms, basestring):
                perms = acp['permissions'].split(',')
            for perm in perms:
                if perm not in ACP_VALUES:
                    raise ServiceError("Invalid ACL permission: %s" % perm)
                if perm not in perm2users:
                    perm2users[perm] = []
                perm2users[perm].append(acp['user'])
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        typ, name = 'Container', container
        headers = {'X-Auth-Token': auth_token}
        query = ''
        if container and manifest:
            typ, name = 'Manifest', name + '/' + manifest
            path = '%s/%s/%s' % (path, quote(container), quote(manifest))
            headers['X-Oneput-Manifest'] = 'true'
            if version_id:
                name += ' version id %s' % version_id
                query += '&versionId=%s' % version_id
        else:
            path = '%s/%s' % (path, quote(container))
        for permission, users in perm2users.items():
            if not manifest:
                if permission == 'WRITE':
                    header_prefix = 'X-Container-'
                else:
                    header_prefix = 'X-Container-Acl-'
            else:
                header_prefix = 'X-Manifest-Acl-'
            header = header_prefix + permission.replace('_', '-').title()
            headers[header] = ','.join(users)
        conn.request('POST', path + query, '', headers)
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               '%s %s: POST ACL failed' % (typ, name))
        return response.status, lower_headers(response.getheaders()), response

    def set_container_acp(self, acl, container, http_conn=None, req_url=None,
                          req_auth_token=None):
        """
        Sets ACL for container.

        :param acl: acl list
        :param container: container name
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                  lowercase), response object)
        :raises ServiceError: if container POST ACL request failed
        """
        return self._set_acp(acl, container, http_conn=http_conn,
                             req_url=req_url, req_auth_token=req_auth_token)

    def set_manifest_acp(self, acl, container, manifest, version_id=None,
                         http_conn=None, req_url=None, req_auth_token=None):
        """
        Sets ACL for manifest.

        :param acl: acl list
        :param container: container name
        :param manifest: manifest name
        :param version_id: version id of manifest
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all lowercase),
                 response object)
        :raises ServiceError: if manifest POST ACL request failed
        """
        return self._set_acp(acl, container, manifest=manifest,
                             version_id=version_id, http_conn=http_conn,
                             req_url=req_url, req_auth_token=req_auth_token)

    def delete_account(self, http_conn=None, req_url=None,
                       req_auth_token=None):
        """
        Deletes an account.

        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all lowercase),
                 response object)
        :raises ServiceError: if account DELETE failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        conn.request('DELETE', path, '', {'X-Auth-Token': auth_token})
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               'Account DELETE failed')
        return response.status, lower_headers(response.getheaders()), response

    def delete_container(self, container, http_conn=None, req_url=None,
                         req_auth_token=None):
        """
        Deletes a container.

        :param container: container name
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all
                 lowercase), response object)
        :raises ServiceError: if container DELETE failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s' % (path, quote(container))
        conn.request('DELETE', path, '', {'X-Auth-Token': auth_token})
        response = conn.getresponse()
        if not is_success(response.status):
            raise ServiceError(response.status, response.read(),
                               'Container %s DELETE failed' % container)
        return response.status, lower_headers(response.getheaders()), response

    def delete_manifest(self, container, manifest, version_id=None,
                        http_conn=None, req_url=None, req_auth_token=None):
        """
        Deletes a manifest.

        :param container: container name
        :param manifest: manifest name to delete
        :param version_id: manifest version id
        :param http_conn: HTTP connection object (If None, it will create the
                          conn object)
        :param req_url: storage URL
        :param req_auth_token: auth token

        :return: a tuple of (response status, response headers (all lowercase),
                 response object)
        :raises ServiceError: manifest DELETE failed
        """
        conn, path, url, auth_token = self.validate_conn(http_conn, req_url,
                                                         req_auth_token)
        path = '%s/%s/%s' % (path, quote(container), quote(manifest))
        query = ''
        if version_id:
            query = '?versionId=%s' % quote(version_id)
        conn.request('DELETE', path + query, '', {'X-Auth-Token': auth_token})
        response = conn.getresponse()
        if not is_success(response.status):
            name = '%s/%s' % (container, manifest)
            if version_id:
                name += ' version id %s' % version_id
            raise ServiceError(response.status, response.read(),
                               'Manifest %s: DELETE failed' % name)
        return response.status, lower_headers(response.getheaders()), response
