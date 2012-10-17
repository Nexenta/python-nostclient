# Copyright 2012 Nexenta Systems Inc.

import os

SCRIPT_NAME = 'nost'

EMPTY_VALUES = ('', None, 0, [], {}, (), set())

TRUE_VALUES = ('true', '1', 'yes', 'on', 't', 'y')

FALSE_VALUES = ('false', '0', 'no', 'off', 'f', 'n')

ACP_VALUES = ('READ', 'READ_ACP', 'WRITE', 'WRITE_ACP', 'FULL_CONTROL')

VERSIONING_VALUES = ('enabled', 'suspended')

CANNED_ACP_VALUES = ('private', 'public-read', 'public-read-write',
                     'authenticated-read', 'container-owner-read',
                     'container-owner-full-control')

# default authorization url
DEFAULT_AUTH_URL = 'http://127.0.0.1:8080/auth/v1.0/'
# default config file path
DEFAULT_CONFIG_PATH = os.path.abspath(os.path.expanduser('~/.nostclient'))
# default section for csclient config
CONFIG_SECTION = 'CONFIG'

KB = 1000
MB = 1000 * KB
GB = 1000 * MB

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

DEFAULT_CHUNK_COUNT = 4

NETWORK_CHUNK_SIZE = 64 * KiB
DISK_CHUNK_SIZE = 64 * KiB

ERROR_CODE = 1
SUCCESS_CODE = 0
