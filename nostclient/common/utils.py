# Copyright 2012 Nexenta Systems Inc.

import os
import sys
import glob
import errno
import logging
from urllib import quote
import cPickle as pickle
from tempfile import mkstemp
from hashlib import md5, sha256

try:
    import simplejson as json
except ImportError:
    import json

from nostclient.common.constants import TRUE_VALUES, FALSE_VALUES


def is_true(v):
    """ Check if v true or false """
    return v.lower() in TRUE_VALUES


def get_logger(name='nostclient_logger', log_level='INFO'):
    """Return properly configurated logger instance"""
    logger = logging.getLogger(name=name)

    # remove pre-existing console handler for this logger
    if not hasattr(get_logger, 'console_handler4logger'):
        get_logger.console_handler4logger = {}
    if logger in get_logger.console_handler4logger:
        logger.removeHandler(get_logger.console_handler4logger[logger])

    # setup console logging
    console_handler = logging.StreamHandler(sys.__stderr__)
    logger.addHandler(console_handler)
    get_logger.console_handler4logger[logger] = console_handler

    # set the level for the logger
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    return logger


def mkdirs(path):
    """
    Ensures the path is a directory or makes it if not. Errors if the path
    exists but is a file or on permissions failure.

    :param path: path to create
    """
    if not os.path.isdir(path):
        try:
            os.makedirs(path)
        except OSError, err:
            if err.errno != errno.EEXIST or not os.path.isdir(path):
                raise


def renamer(old, new):
    """
    Attempt to fix / hide race conditions like empty object directories
    being removed by backend processes during uploads, by retrying.

    :param old: old path to be renamed
    :param new: new path to be renamed to
    """
    try:
        mkdirs(os.path.dirname(new))
        os.rename(old, new)
    except OSError:
        mkdirs(os.path.dirname(new))
        os.rename(old, new)


def remove_file(path):
    """
    Quiet wrapper for os.unlink, OSErrors are suppressed

    :param path: first and only argument passed to os.unlink
    """
    try:
        os.unlink(path)
    except OSError:
        pass


def validate_path(path):
    """
    Validates file path

    :param path: path of file to validate.
    Like /home/<usr_name>/<file_name> or ~/.<config_file_name>
    """
    return os.path.abspath(os.path.expanduser(path))


def validate_obj_name(arg):
    try:
        name = str(arg)
        if name.startswith('./') or name.startswith('~/'):
            val_name = name[2:]
        elif name.startswith('../'):
            val_name = name[3:]
        else:
            val_name = name
        return val_name
    except ValueError, e:
        raise ValueError(e)


def cast_value(value):
    if value.isdigit():
        return int(value)
    try:
        return float(value)
    except ValueError:
        pass
    if value.lower() in TRUE_VALUES:
        return True
    elif value.lower() in FALSE_VALUES:
        return False
    return value


def split_path(path, minsegs=1, maxsegs=None, rest_with_last=False):
    """
    Validate and split the given HTTP request path.

    **Examples**::

        ['a'] = split_path('/a')
        ['a', None] = split_path('/a', 1, 2)
        ['a', 'c'] = split_path('/a/c', 1, 2)
        ['a', 'c', 'o/r'] = split_path('/a/c/o/r', 1, 3, True)

    :param path: HTTP Request path to be split
    :param minsegs: Minimum number of segments to be extracted
    :param maxsegs: Maximum number of segments to be extracted
    :param rest_with_last: If True, trailing data will be returned as part
                           of last segment.  If False, and there is
                           trailing data, raises ValueError.
    :returns: list of segments with a length of maxsegs (non-existant
              segments will return as None)
    :raises: ValueError if given an invalid path
    """
    if not maxsegs:
        maxsegs = minsegs
    if minsegs > maxsegs:
        raise ValueError('minsegs > maxsegs: %d > %d' % (minsegs, maxsegs))
    if rest_with_last:
        segs = path.split('/', maxsegs)
        minsegs += 1
        maxsegs += 1
        count = len(segs)
        if (segs[0] or count < minsegs or count > maxsegs or
                '' in segs[1:minsegs]):
            raise ValueError('Invalid path: %s' % quote(path))
    else:
        minsegs += 1
        maxsegs += 1
        segs = path.split('/', maxsegs)
        count = len(segs)
        if (segs[0] or count < minsegs or count > maxsegs + 1 or
                '' in segs[1:minsegs] or
                (count == maxsegs + 1 and segs[maxsegs])):
            raise ValueError('Invalid path: %s' % quote(path))
    segs = segs[1:maxsegs]
    segs.extend([None] * (maxsegs - 1 - len(segs)))
    return segs


def hash_path(account, container=None, object=None, raw_digest=False):
    """
    Get the canonical hash for an account/container/object

    :param account: Account
    :param container: Container
    :param object: Object
    :param raw_digest: If True, return the raw version rather than a hex digest
    :returns: hash string
    """
    if object and not container:
        raise ValueError('container is required if object is provided')
    paths = [account]
    if container:
        paths.append(container)
    if object:
        paths.append(object)
    hash_func = sha256 if RING_TYPE == 's1ring' else md5
    if raw_digest:
        return hash_func('/' + '/'.join(paths) + HASH_PATH_SUFFIX).digest()
    else:
        return hash_func('/' + '/'.join(paths) + HASH_PATH_SUFFIX).hexdigest()


def write_pickle(obj, dest, tmp=None, pickle_protocol=0):
    """
    Ensure that a pickle file gets written to disk.  The file
    is first written to a tmp location, ensure it is synced to disk, then
    perform a move to its final location

    :param obj: python object to be pickled
    :param dest: path of final destination file
    :param tmp: path to tmp to use, defaults to None
    :param pickle_protocol: protocol to pickle the obj with, defaults to 0
    """
    if tmp is None:
        tmp = os.path.dirname(dest)
    fd, tmppath = mkstemp(dir=tmp, suffix='.tmp')
    with os.fdopen(fd, 'wb') as fo:
        pickle.dump(obj, fo, pickle_protocol)
        fo.flush()
        os.fsync(fd)
        renamer(tmppath, dest)


def search_tree(root, glob_match, ext):
    """Look in root, for any files/dirs matching glob, recurively traversing
    any found directories looking for files ending with ext

    :param root: start of search path
    :param glob_match: glob to match in root, matching dirs are traversed with
                       os.walk
    :param ext: only files that end in ext will be returned

    :returns: list of full paths to matching files, sorted

    """
    found_files = []
    for path in glob.glob(os.path.join(root, glob_match)):
        if path.endswith(ext):
            found_files.append(path)
        else:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(ext):
                        found_files.append(os.path.join(root, file))
    return sorted(found_files)


def get_remote_client(req):
    # remote host for zeus
    client = req.headers.get('x-cluster-client-ip')
    if not client and 'x-forwarded-for' in req.headers:
        # remote host for other lbs
        client = req.headers['x-forwarded-for'].split(',')[0].strip()
    if not client:
        client = req.remote_addr
    return client


def human_readable(value):
    """
    Returns the number in a human readable format; for example 1048576 = "1Mi".
    """
    value = float(value)
    index = -1
    suffixes = 'KMGTPEZY'
    while value >= 1024 and index + 1 < len(suffixes):
        index += 1
        value = round(value / 1024)
    if index == -1:
        return '%d' % value
    return '%d%si' % (round(value), suffixes[index])


def listdir(path):
    try:
        return os.listdir(path)
    except OSError, err:
        if err.errno != errno.ENOENT:
            raise
    return []
