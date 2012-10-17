# Copyright 2012 Nexenta Systems Inc.

import sys
import optparse

from nostclient.client import NSclient
from nostclient.common.config import Config
from nostclient.common.utils import validate_path
from nostclient.common.constants import ERROR_CODE, SUCCESS_CODE, SCRIPT_NAME


USAGE = """
%s delete container [manifest]

Deletes container or manifest depending on the args given (if any).
""".strip('\n') % SCRIPT_NAME


def action(parser, args):
    group = optparse.OptionGroup(parser, 'Delete options')
    group.add_option('--version-id', dest='version_id', action='store',
                     default=None, help='delete given manifest version id')
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
    if not args or len(args) > 2:
        parser.print_usage()
        return ERROR_CODE
    if len(args) != 2 and options.version_id:
        print >> sys.stderr, 'ERROR: version id allowed only if manifest ' \
                             'specified'
        return ERROR_CODE
    if len(args) == 1:
        client.delete_container(args[0])
        typ, name = 'Container', args[0]
    elif len(args) == 2:
        client.delete_manifest(args[0], args[1], version_id=options.version_id)
        typ, name = 'Manifest', '%s/%s' % (args[0], args[1])
        if options.version_id:
            name += ' version id %s' % options.version_id
    print >> sys.stdout, '%s was successfully deleted' % name
    return SUCCESS_CODE
