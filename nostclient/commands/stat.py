# Copyright 2012 Nexenta Systems Inc.

import sys
import optparse

from nostclient.client import NSclient
from nostclient.common.config import Config
from nostclient.common.http import is_success
from nostclient.common.utils import validate_path
from nostclient.common.constants import ERROR_CODE, SUCCESS_CODE, SCRIPT_NAME


USAGE = """
%s stat [container] [manifest]

Displays information for the account, container or manifest depending on the
args given (if any).
""".strip('\n') % SCRIPT_NAME

SKIP_HEADERS = ('date', 'x-timestamp', 'content-type', 'accept-ranges')


def action(parser, args):
    group = optparse.OptionGroup(parser, 'Stat options')
    group.add_option('--version-id', dest='version_id', action='store',
                     default=None, help='stat about object given version id')
    parser.add_option_group(group)
    parser.usage = USAGE
    (options, args) = parser.parse_args(args)
    cfg_file_path = validate_path(options.cfg_file)
    config = Config(cfg_file_path, options)
    client = NSclient(
        auth_url=config.auth_url, auth_version=config.auth_version,
        user=config.user, key=config.key, proxy_host=config.proxy_host,
        proxy_port=config.proxy_port, proxy_user=config.proxy_user,
        proxy_pass=config.proxy_pass, debug=False)
    if len(args) < 2 and options.version_id:
        print >> sys.stderr, 'ERROR: --version-id allowed only for object'
        return ERROR_CODE
    kwargs = {}
    if not args:
        prefix = 'x-account-'
        func = client.stat_account
    elif len(args) == 1:
        prefix = 'x-container-'
        func = client.stat_container
    elif len(args) == 2:
        prefix = 'x-manifest-'
        func = client.stat_manifest
        kwargs['version_id'] = options.version_id
    status, headers, response = func(*args, **kwargs)
    if not is_success(status):
        print >> sys.stderr, response.read()
        return ERROR_CODE
    out = []
    for header, value in headers.items():
        if header not in SKIP_HEADERS:
            if header.startswith(prefix):
                header = header[len(prefix):]
            elif header.startswith('x-'):
                header = header[2:]
            header = header.replace('-', ' ').capitalize()
            out.append('%s: %s' % (header, value))
    if out:
        print >> sys.stdout, '\n'.join(out)
    return SUCCESS_CODE
