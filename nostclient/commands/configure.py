# Copyright 2012 Nexenta Systems Inc.

from __future__ import with_statement
import os
import sys

from nostclient.common.config import Config
from nostclient.common.utils import is_true, renamer, validate_path
from nostclient.common.exceptions import ValidationError, OptionError
from nostclient.common.validators import NotEmptyValidator, NotUrlValidator
from nostclient.common.constants import DEFAULT_CONFIG_PATH, ERROR_CODE, \
    SUCCESS_CODE, EMPTY_VALUES, SCRIPT_NAME


USAGE = """
%s configure [options]

Save configs to config file, default file path is %s.
""".strip('\n') % (SCRIPT_NAME, DEFAULT_CONFIG_PATH)


def action(parser, args):
    parser.usage = USAGE
    (opts, args) = parser.parse_args(args)
    cfg_file_path = validate_path(opts.cfg_file)
    config = Config(cfg_file_path)
    if not os.path.exists(os.path.split(cfg_file_path)[0]):
        raise OptionError('Invalid path for configuration file: %s' %
                          cfg_file_path)
    #TODO: if already exists cfg_file, ask whether to make a change
    options = [
        ('auth_url', 'Authorization url', 'URL for obtaining an auth token',
         (NotEmptyValidator('Please define authorization url'),
          NotUrlValidator('Invalid url value'))),
        ('auth_version', 'Authorization version',
         'Specify a version for authentication (default: 1.0)',
         (NotEmptyValidator('Please authorization version'), )),
        ('user', 'User', 'User name for obtaining an auth token',
         (NotEmptyValidator('Please define user'), )),
        ('key', 'Key', 'Key for obtaining an auth token',
         (NotEmptyValidator('Please define key'), ))
    ]
    print >> sys.stdout, 'Configure csclient.'
    print >> sys.stdout, 'Enter new values or accept defaults in brackets ' \
                         'with Enter.'
    print >> sys.stdout
    for key, name, description, validators in options:
        print >> sys.stdout, description
        default = getattr(config, key)
        if default:
            promt = '%s [%s]: ' % (name, default)
        else:
            promt = '%s: ' % name
        if not isinstance(validators, (list, tuple)):
            validators = tuple(validators)
        while True:
            value = raw_input(promt) or default
            try:
                for validator in validators:
                    value = validator(value)
            except ValidationError, e:
                print >> sys.stderr, 'ERROR: %s' % e
                continue
            break
        setattr(config, key, value)
    save = raw_input("Save configuration parameters in %s ([y]/n): " %
                     cfg_file_path) or 'yes'
    if not is_true(save):
        print >> sys.stdout, 'Configuration parameters wasn\'t saved'
        return SUCCESS_CODE
    while os.path.exists(cfg_file_path):
        overwrite = raw_input("File %s already exists, overwrite it? "
                              "(y/[n]): " % cfg_file_path) or 'no'
        if is_true(overwrite):
            backup = raw_input("Create backup of %s? ([y]/n)" %
                               cfg_file_path) or 'yes'
            if is_true(backup):
                idx = 0
                backup_file = '%s.bkp' % cfg_file_path
                while os.path.exists(backup_file):
                    idx += 1
                    backup_file = '%s.bkp_%s' % (cfg_file_path, idx)
                try:
                    renamer(cfg_file_path, backup_file)
                    print >> sys.stdout, ("File %s was successfully moved to "
                                          "%s" % (cfg_file_path, backup_file))
                except IOError:
                    print >> sys.stderr, "ERROR: Cannot move %s to %s" % \
                                         (cfg_file_path, backup_file)
        else:
            while True:
                cfg_file_path = raw_input("Input path to file for saving "
                                          "configuration parameters: ")
                if cfg_file_path in EMPTY_VALUES:
                    print >> sys.stderr, "ERROR: Please define path to " \
                                         "configuration file"
                    continue
                break
        break
    try:
        config.save_config(cfg_file_path)
        print >> sys.stdout, "Configuration parameters was successfully " \
                             "saved in %s" % cfg_file_path
    except IOError:
        print >> sys.stderr, "ERROR: Cannot save configuration file: %s" % \
                             cfg_file_path
        return ERROR_CODE
    return SUCCESS_CODE
