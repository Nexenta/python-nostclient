# Copyright 2012 Nexenta Systems Inc.

import sys
import optparse

from nostclient.client import NSclient
from nostclient.common.config import Config
from nostclient.common.constants import ERROR_CODE, SUCCESS_CODE, SCRIPT_NAME


USAGE = """
%s list [container] [manifest] [options]

Shows list for the account, container or list of chunks from the manifest
depending on the args given (if any).
""".strip('\n') % SCRIPT_NAME


def action(parser, args):
    group = optparse.OptionGroup(parser, 'List options')
    group.add_option('-f', '--full', dest='full', default=False,
                     action='store_true', help='full listing of objects')
    group.add_option('-l', '--limit', dest='limit', default=None,
                     action='store', help='limit for items to show')
    group.add_option('-p', '--prefix', dest='prefix', default=None,
                     action='store',  help='shows only list items beginning '
                     'with that prefix')
    group.add_option('-d', '--delimiter', dest='delimiter', default=None,
                     action='store', help='rolls up items with the given '
                     'delimiter')
    group.add_option('-m', '--marker', dest='marker', default=None,
                     action='store', help='rolls up items with the given '
                     'marker')
    group.add_option('--end-marker', dest='end_marker', default=None,
                     action='store', help='rolls up items which less then '
                     'the given marker')
    group.add_option('--versions', dest='versions', action='store_true',
                     default=False, help='shows only list items having '
                     'version_id (for container listings only)')
    group.add_option('--vmarker', dest='vmarker', default=None, action='store',
                     help='rolls up items with the given '
                     'vmarker for version id (for container listings only)')
    group.add_option('--end-vmarker', dest='end_vmarker', default=None,
                     action='store', help='rolls up items which version id '
                     'less then the given vmarker (for container listings '
                     'only)')
    group.add_option('--version-id', dest='version_id', action='store',
                     default=None, help='list chunks of given version id')
    parser.add_option_group(group)
    parser.usage = USAGE
    (options, args) = parser.parse_args(args)
    opts = [options.limit, options.prefix, options.delimiter, options.marker,
            options.end_marker, options.versions, options.vmarker,
            options.end_vmarker]
    if len(args) >= 3 and any(opts):
        print >> sys.stderr, 'ERROR: options not allowed for manifest'
        return ERROR_CODE
    if len(args) != 1 and any(opts[:-3]):
        print >> sys.stderr, 'ERROR: version options allowed only for ' \
                             'container'
        return ERROR_CODE
    if any(opts[-2:]) and not options.versions:
        print >> sys.stderr, 'ERROR: --vmarker and --end-vmarker allowed ' \
                             'only with --versions'
        return ERROR_CODE
    config = Config(options.cfg_file, options)
    client = NSclient(
        auth_url=config.auth_url, auth_version=config.auth_version,
        user=config.user, key=config.key, proxy_host=config.proxy_host,
        proxy_port=config.proxy_port, proxy_user=config.proxy_user,
        proxy_pass=config.proxy_pass, debug=False)
    marker = ''
    kwargs = {}
    if len(args) <= 1:
        kwargs.update({
            'marker': options.marker, 'end_marker': options.end_marker,
            'limit': options.limit, 'prefix': options.prefix,
            'delimiter': options.delimiter, 'full_listing': options.full})
        if options.versions:
            kwargs.update({'vmarker': options.vmarker,
                           'end_vmarker': options.end_vmarker})
    out = []
    if len(args) == 0:
        containers = client.get_account(**kwargs)[2]
        for container in containers:
            out.append('%(name)s' % container)
    elif len(args) == 1:
        if options.versions:
            func = client.get_versions_list
        else:
            func = client.get_container
        manifests = func(args[0], **kwargs)[2]
        for manifest in manifests:
            s = manifest.get('name', manifest.get('subdir'))
            if 'version_id' in manifest:
                s += ' ' + manifest['version_id']
            out.append(s)
    else:
        kwargs['version_id'] = options.version_id
        manifest = client.get_manifest(args[0], args[1], **kwargs)[2]
        chunk_size = manifest.get('chunk_size')
        for chunk in manifest.get('chunks', []):
            hash, size = chunk['hash'], chunk.get('size', chunk_size)
            out.append('%s %d' % (hash, size))
    if out:
        print >> sys.stdout, '\n'.join(out)
    return SUCCESS_CODE
