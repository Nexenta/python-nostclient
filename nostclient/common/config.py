# Copyright 2012 Nexenta Systems Inc.

from __future__ import with_statement
import os
import ConfigParser

from nostclient.common.constants import NETWORK_CHUNK_SIZE, DISK_CHUNK_SIZE, \
    CONFIG_SECTION, DEFAULT_CONFIG_PATH, EMPTY_VALUES
from nostclient.common.utils import cast_value


class ConfigData(object):
    """
    Class for storing nostclient configuration parameters

    To add new configuration parameter just define it in ConfigData
    declaration.
    """

    auth_url = 'http://127.0.0.1:8080/auth/v1.0/'
    auth_version = '1.0'
    user = ''
    key = ''

    network_chunk_size = NETWORK_CHUNK_SIZE
    disk_chunk_size = DISK_CHUNK_SIZE

    # Host of HTTP proxy
    proxy_host = ''
    # Port of HTTP proxy
    proxy_port = ''
    # User for HTTP proxy
    proxy_user = ''
    # Password for user HTTP proxy
    proxy_pass = ''


def config_value(params, config, name, value):
    if value and hasattr(config, name):
        default = getattr(config, name)
        if default in EMPTY_VALUES:
            params[name] = cast_value(value)
        elif isinstance(default, basestring):
            params[name] = value
        else:
            params[name] = cast_value(value)


class Config(object):

    config_path = None
    config = None
    options = None

    def __init__(self, config_path=None, options=None):
        self.config_path = config_path if config_path else DEFAULT_CONFIG_PATH
        self.config = ConfigData()
        self.options = options or {}
        self.load_config()

    def load_config(self):
        """ Load configuration parameters from config to _config """
        params = {}
        if self.config_path and os.path.exists(self.config_path):
            parser = ConfigParser.ConfigParser()
            parser.read(self.config_path)
            if parser.has_section(CONFIG_SECTION):
                for name, value in parser.items(CONFIG_SECTION):
                    config_value(params, ConfigData, name, value)
        if self.options:
            if isinstance(self.options, dict):
                for name, value in self.options.items():
                    config_value(params, ConfigData, name, value)
            else:
                for name in ConfigData.__dict__:
                    if not name.startswith('__'):
                        if hasattr(self.options, name):
                            value = getattr(self.options, name)
                            config_value(params, ConfigData, name, value)
        for key, value in ConfigData.__dict__.items():
            if not key.startswith('__'):
                val = params[key] if key in params else value
                setattr(self.config, key, val)

    def save_config(self, config_path=None):
        """
        Save configuration parameters to file in python ConfigParser format

        :param config_path: path to configuration file, if not defined will be
                            used default
        """
        config_path = config_path if config_path else self.config_path
        if not config_path:
            return
        parser = ConfigParser.ConfigParser()
        parser.add_section(CONFIG_SECTION)
        for name in dir(self.config):
            if name.startswith('__'):
                continue
            value = getattr(self.config, name)
            parser.set(CONFIG_SECTION, name, value)
        with open(config_path, 'wb') as fd:
            parser.write(fd)

    def to_dict(self):
        d = {}
        for attr in self.config.__dict__:
            if not attr.startswith('__'):
                d[attr] = self.config.__dict__[attr]
        return d

    def __getattribute__(self, key):
        if key in Config.__dict__:
            return super(Config, self).__getattribute__(key)
        return getattr(self.config, key)

    def __setattr__(self, key, value):
        if key in Config.__dict__:
            return super(Config, self).__setattr__(key, value)
        return setattr(self.config, key, value)
