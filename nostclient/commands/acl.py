# Copyright 2012 Nexenta Systems Inc.

import sys
import optparse

from nostclient.client import NSclient
from nostclient.common.config import Config
from nostclient.common.http import is_success
from nostclient.common.utils import validate_path
from nostclient.common.constants import ERROR_CODE, SUCCESS_CODE, ACP_VALUES, \
    SCRIPT_NAME


USAGE = """
%s acl container [manifest]

Displays ACL information for the container or manifest depending on the args
given (if any).
""".strip('\n') % SCRIPT_NAME


def action(parser, args):
    group = optparse.OptionGroup(parser, 'ACL options')
    group.add_option(
        '--acp', dest='acp', default=None, action='store',
        help='acl for resource, for example account:user READ_ACP')
    group.add_option(
        '--version-id', dest='version_id', action='store', default=None,
        help='allows to get or set acl for given manifest version id')
    parser.add_option_group(group)
    parser.usage = USAGE
    (options, args) = parser.parse_args(args)
    if not args or len(args) > 2:
        parser.print_usage()
        return ERROR_CODE
    if len(args) == 1 and options.version_id:
        print >> sys.stderr, "ERROR: version id option allowed only for " \
                             "manifest operation"
        return ERROR_CODE
    cfg_file_path = validate_path(options.cfg_file)
    config = Config(cfg_file_path, options)
    client = NSclient(
        auth_url=config.auth_url, auth_version=config.auth_version,
        user=config.user, key=config.key, proxy_host=config.proxy_host,
        proxy_port=config.proxy_port, proxy_user=config.proxy_user,
        proxy_pass=config.proxy_pass, debug=False)
    if options.acp:
        permissions = [p.strip() for p in options.acp.split(';') if p.strip()]
        acl = []
        for permission in permissions:
            if ' ' not in permission:
                print >> sys.stderr, "ERROR: Invalid permission %s" % \
                                     permission
                return ERROR_CODE
            user, perms = permission.split(' ', 1)
            perms = [p.strip() for p in perms.split(',') if p.strip()]
            for p in perms:
                if p not in ACP_VALUES:
                    print >> sys.stderr, "ERROR: Invalid permission %s" % \
                                         permission
                    return ERROR_CODE
            acl.append({'user': user, 'permissions': ','.join(perms)})
        kwargs = {}
        if len(args) == 1:
            func = client.set_container_acp
        elif len(args) == 2:
            func = client.set_manifest_acp
            kwargs['version_id'] = options.version_id
        status, headers, response = func(acl, *args, **kwargs)
        if not is_success(status):
            print >> sys.stderr, response.read()
            return ERROR_CODE
        return SUCCESS_CODE
    kwargs = {}
    if len(args) == 1:
        func = client.get_container_acp
    elif len(args) == 2:
        func = client.get_manifest_acp
        kwargs['version_id'] = options.version_id
    status, headers = func(*args, **kwargs)
    typ = 'container' if len(args) == 1 else 'manifest'
    if 'x-%s-owner' % typ in headers:
        print >> sys.stdout, 'Owner: %s' % headers['x-%s-owner' % typ]
    permissions = {}
    for header in headers:
        key = None
        if typ == 'container':
            if header in ('x-container-read', 'x-container-write'):
                key = header[12:]
            elif header.startswith('x-container-acl-'):
                key = header[16:].replace('-', '_')
        else:
            if header.startswith('x-manifest-acl-'):
                key = header[15:].replace('-', '_')
        if key:
            permissions[key] = [u.strip() for u in headers[header].split(',')
                                if u.strip()]
    for key, value in permissions.iteritems():
        if value:
            print >> sys.stdout, '%s: %s' % (key.replace('_', ' ').title(),
                                             ', '.join(value))
    return SUCCESS_CODE
