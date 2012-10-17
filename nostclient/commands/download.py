# Copyright 2012 Nexenta Systems Inc.

from __future__ import with_statement
import os
import sys
import optparse
from hashlib import md5, sha256

from nostclient.client import NSclient
from nostclient.common.utils import mkdirs
from nostclient.common.config import Config
from nostclient.common.progressbar import ProgressBar
from nostclient.common.constants import ERROR_CODE, SUCCESS_CODE, SCRIPT_NAME


USAGE = """
%s download container manifest [chunk] [options]

Downloads from the given container files specified by the remaining args.
""".strip('\n') % SCRIPT_NAME


def action(parser, args):
    group = optparse.OptionGroup(parser, 'Download options')
    group.add_option('--version-id', dest='version_id', action='store',
                     default=None, help='download object given version id')
    group.add_option('-q', '--quite', dest='quite', action='store_true',
                     default=False, help='hide progress bar')
    group.add_option('--only-manifest', dest='only_manifest', default=False,
                     action='store_true', help='download only manifest')
    group.add_option('--only-chunk', dest='only_chunk', default=False,
                     action='store_true', help='download only given chunk')
    parser.add_option_group(group)
    parser.usage = USAGE
    (options, args) = parser.parse_args(args)
    if not args or len(args) < 2:
        print >> sys.stderr, 'ERROR: download allowed only for given object ' \
                             'or chunk.'
        return ERROR_CODE
    if options.only_manifest and options.only_chunk:
        print >> sys.stderr, 'ERROR: --only-manifest and --only-chunk ' \
                             'options not allowed together.'
        return ERROR_CODE
    if options.only_chunk and len(args) != 3:
        print >> sys.stderr, 'ERROR: for --only-chunk required chunk.'
        return ERROR_CODE
    if not options.only_chunk and len(args) >= 3:
        print >> sys.stderr, 'ERROR: chunk allowed if --only-chunk presented'
        return ERROR_CODE
    config = Config(options.cfg_file, options)
    client = NSclient(
        auth_url=config.auth_url, auth_version=config.auth_version,
        user=config.user, key=config.key, proxy_host=config.proxy_host,
        proxy_port=config.proxy_port, proxy_user=config.proxy_user,
        proxy_pass=config.proxy_pass, debug=False)
    if options.only_manifest:
        manifest = client.get_manifest(*args, version_id=options.version_id)[2]
        print >> sys.stdout, manifest
        return SUCCESS_CODE
    elif options.only_chunk:
        resp = client.get_chunk(args[0], args[1], args[2])[2]
        data_source = iter(lambda: resp.read(config.network_chunk_size), '')
        filename = args[2]
        typ = 'Chunk'
        title = '%s/%s' % (args[1], args[2])
        etag = args[2]
        hash = sha256()
        content_length = resp.length
        content_type = None
    else:
        status, resp_headers, resp = \
            client.get_object(args[0], args[1], version_id=options.version_id)
        data_source = resp
        filename = args[1]
        typ = 'Object'
        title = args[1]
        etag = resp.etag
        hash = md5()
        content_length = resp.content_length
        content_type = resp_headers.get('content-type')
    if content_type == 'text/directory':
        if not os.path.isdir(filename):
            mkdirs(filename)
        return SUCCESS_CODE
    dirpath = os.path.dirname(filename)
    if dirpath and not os.path.isdir(dirpath):
        mkdirs(filename)
    if os.path.isdir(filename):
        return SUCCESS_CODE
    bar = ProgressBar(content_length, title=title, quite=options.quite)
    bar.start()
    with open(filename, 'wb') as fdp:
        for chunk in data_source:
            fdp.write(chunk)
            if bar:
                bar.value += len(chunk)
            hash.update(chunk)
    bar.finish()
    if etag != hash.hexdigest():
        print >> sys.stderr, 'ERROR: %s %s download failed, hashes are '\
                             'not equals' % (typ, title)
        return ERROR_CODE
    return SUCCESS_CODE
