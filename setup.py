#!/bin/env python
# Copyright 2012 Nexenta Systems Inc.

from setuptools import setup, find_packages

from nostclient import __canonical_version__ as version


name = 'csclient'


setup(
    name=name,
    version=version,
    description='Cloudstorag console client',
    license='Apache License (2.0)',
    author='Nexenta Systems Inc.',
    author_email='victor.rodionov@nexenta.com',
    packages=find_packages(exclude=['test', 'bin']),
    test_suite='nose.collector',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.6',
        'Environment :: No Input/Output (Daemon)',
        ],
    install_requires=[],
    scripts=[
        'bin/csclient'
    ]
)
