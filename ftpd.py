#!/usr/bin/python3
# -*- coding: utf-8 -*-
import logging

from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer

logging.basicConfig(filename='/tmp/ftpd.log', level=logging.DEBUG)


class HuntingFTPHandler(FTPHandler):
    banner = 'rpc'


authorizer = DummyAuthorizer()
authorizer.add_user('test', 'test', '/tmp/', perm='fmw')

handler = HuntingFTPHandler
handler.authorizer = authorizer

ftp = FTPServer(('127.0.0.1', '8021'), handler)
ftp.serve_forever()
