# Copyright 2012 Nexenta Systems Inc.

import os
import sys
import optparse

from nostclient.client import NSclient
from nostclient.common.config import Config
from nostclient.common.progressbar import ProgressBar
from nostclient.common.constants import SUCCESS_CODE, ERROR_CODE, MiB, \
    SCRIPT_NAME
from nostclient.common.utils import validate_path, validate_obj_name


USAGE = """
%s upload [container] [file] [options]

Uploads to the given container the files specified by the remaining args.
""".strip('\n') % SCRIPT_NAME


def filepath_generator(path, prefix):
    """ Simple filepath generator """
    isdir = os.path.isdir(path)
    yield (isdir, path, prefix)
    if isdir:
        for filename in os.listdir(path):
            _path = os.path.join(path, filename)
            for i in filepath_generator(_path, prefix + '/' + filename):
                yield i


def action(parser, args):
    group = optparse.OptionGroup(parser, 'Upload options')
    group.add_option('--only-placeholder', dest='only_placeholder',
                     help='upload only manifest placeholder', default=False,
                     action='store_true')
    group.add_option('--only-manifest', dest='only_manifest', default=False,
                     help='upload only manifest', action='store_true')
    group.add_option('--only-chunk', dest='only_chunk', default=False,
                     help='upload only chunk', action='store_true')
    group.add_option('--chunk', dest='chunk', action='store',
                     help='path to chunk file')
    group.add_option('--session-id', dest='session_id', action='store',
                     help='manifest session ID')
    group.add_option('--session-timestamp', dest='session_timestamp',
                     action='store', help='manifest session timestamp')
    group.add_option('--chunk-size', dest='chunk_size', type='int',
                     action='store', help='chunk size', default=MiB)
    group.add_option('-w', '--workers', dest='workers', type='int',
                     action='store', default=5,
                     help='number of workers threads')
    group.add_option('-q', '--quite', dest='quite', action='store_true',
                     default=False, help='hide progress bar')
    parser.add_option_group(group)
    parser.usage = USAGE
    (options, args) = parser.parse_args(args)
    config = Config(options.cfg_file, options)
    client = NSclient(
        auth_url=config.auth_url, auth_version=config.auth_version,
        user=config.user, key=config.key, proxy_host=config.proxy_host,
        proxy_port=config.proxy_port, proxy_user=config.proxy_user,
        proxy_pass=config.proxy_pass, debug=False)

    conn, path, req_url, req_auth_token = client.validate_conn()

    # PUT account
    if not args:
        client.put_account(http_conn=conn, req_url=req_url,
                           req_auth_token=req_auth_token)
        return SUCCESS_CODE

    headers = {}

    # PUT container
    if len(args) == 1:
        client.put_container(args[0], headers=headers, http_conn=conn,
                             req_url=req_url, req_auth_token=req_auth_token)
        return SUCCESS_CODE

    container_name, object_name = args[0], args[1]
    try:
        object_name = validate_obj_name(object_name)
    except ValueError:
        print >> sys.stderr, 'ERROR: Invalid object name: %s' % args[1]
        return ERROR_CODE

    # PUT placeholder
    if options.only_placeholder:
        session_id, session_timestamp =\
            client.put_placeholder(
                container_name, object_name, http_conn=conn, req_url=req_url,
                req_auth_token=req_auth_token)
        print >> sys.stdout, 'Session id: %s\nSession timestamp: %s' % \
                             (session_id, session_timestamp)
        return SUCCESS_CODE

    filepath = validate_path(args[1])
    if not os.path.exists(filepath):
        print >> sys.stderr, 'ERROR: File %s does not exists' % filepath
        return ERROR_CODE

    for isdir, path, name in filepath_generator(filepath, object_name):
        if isdir:
            client.put_directory(container_name, name + '/')
            continue
        kwargs = {'chunk_size': options.chunk_size, 'workers': options.workers}
        info = os.stat(path)
        bar = ProgressBar(max_value=info.st_size, title=name,
                          quite=options.quite)
        bar.start()
        kwargs['callback'] = bar.callback
        kwargs['error_callback'] = bar.clear
        try:
            with open(path, 'rb') as fp:
                client.put_object(container_name, name, fp, headers=headers,
                                  http_conn=conn, req_url=req_url,
                                  req_auth_token=req_auth_token, **kwargs)
        except Exception, e:
            bar.clear()
            raise e
        bar.finish()

    return SUCCESS_CODE
