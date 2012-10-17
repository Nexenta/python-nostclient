# Copyright 2012 Nexenta Systems Inc.

import os
import unittest
import tempfile
from shutil import rmtree

from nostclient.common.config import Config
from nostclient.common.constants import NETWORK_CHUNK_SIZE, DISK_CHUNK_SIZE, \
    DEFAULT_AUTH_URL


class TestConfig(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp('test_config')

    def tearDown(self):
        rmtree(self.tmp_dir)

    def test_config(self):
        cfg_path = os.path.join(self.tmp_dir, '.csclient')
        cfg = Config(cfg_path)
        self.assertEqual(cfg.auth_url, DEFAULT_AUTH_URL)
        self.assertEqual(cfg.auth_version, '1.0')
        self.assertEqual(cfg.user, '')
        self.assertEqual(cfg.key, '')
        self.assertEqual(cfg.network_chunk_size, NETWORK_CHUNK_SIZE)
        self.assertEqual(cfg.disk_chunk_size, DISK_CHUNK_SIZE)
        cfg.user = 'admin:admin'
        cfg.key = 'admin'
        cfg.not_in_config_parameter = '123'
        cfg.save_config()
        self.assertEquals(os.listdir(self.tmp_dir), ['.csclient'])
        self.assertTrue(os.path.exists(cfg_path))

        cfg = Config(cfg_path)
        self.assertEqual(cfg.user, 'admin:admin')
        self.assertEqual(cfg.key, 'admin')
        self.assertEqual(cfg.disk_chunk_size, DISK_CHUNK_SIZE)
        self.assertRaises(AttributeError, lambda: cfg.not_in_config_parameter)

        data = cfg.to_dict()
        self.assertEqual(data['disk_chunk_size'], DISK_CHUNK_SIZE)
        self.assertEqual(data['network_chunk_size'], NETWORK_CHUNK_SIZE)
        self.assertEqual(data['auth_url'], 'http://127.0.0.1:8080/auth/v1.0/')
        self.assertEqual(data['user'], 'admin:admin')
        self.assertEqual(data['key'], 'admin')
        self.assertEqual(data['auth_version'], '1.0')
        self.assertEqual(data['proxy_host'], '')
        self.assertEqual(data['proxy_port'], '')


if __name__ == '__main__':
    unittest.main()
