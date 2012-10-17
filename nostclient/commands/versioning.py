# Copyright 2012 Nexenta Systems Inc.

import sys

from nostclient.client import NSclient
from nostclient.common.config import Config
from nostclient.common.constants import ERROR_CODE, SUCCESS_CODE, \
    VERSIONING_VALUES, SCRIPT_NAME


USAGE = """
%s versioning container [enabled|suspended]

Shows versioning status for given container or set versioning status for
container if given third argument.
""".strip('\n') % SCRIPT_NAME


def action(parser, args):
    parser.usage = USAGE
    (options, args) = parser.parse_args(args)
    config = Config(options.cfg_file, options)
    client = NSclient(
        auth_url=config.auth_url, auth_version=config.auth_version,
        user=config.user, key=config.key, proxy_host=config.proxy_host,
        proxy_port=config.proxy_port, proxy_user=config.proxy_user,
        proxy_pass=config.proxy_pass, debug=False)
    if not args:
        parser.print_usage()
        return ERROR_CODE
    elif len(args) == 1:
        _junk, _junk, _junk, versioning = client.get_versioning(args[0])
        print >> sys.stdout, 'Container %s versioning is %s' % \
                             (args[0], versioning)
    elif len(args) == 2:
        if args[1] not in VERSIONING_VALUES:
            print >> sys.stderr, 'ERROR: Invalid versioning status: %s' % \
                                 args[1]
            return ERROR_CODE
        client.set_versioning(args[0], args[1])[0]
    return SUCCESS_CODE
