#!/usr/bin/python3
# -*- coding: utf-8 -*-

import getopt
import os
import select
import socket
import sys
import threading
from Queue import Queue
from tkinter import *

debug = False
buffer_size = 1024 * 2


def print_msg(msg):
    if debug:
        print msg


# this is a pretty hex dumping function directly taken from
# http://code.activestate.com/recipes/142812-hex-dumper/
def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2

    for i in xrange(0, len(src), length):
        s = src[i:i + length]
        hexa = b' '.join(['%0*X' % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b'%04X   %-*s   %s' % (i, length * (digits + 1), hexa, text))
    print b'\n'.join(result)


def forward(sock, target_sock, head_data=''):
    data = head_data + sock.recv(buffer_size)
    if data:
        if debug:
            s_addr, s_port = sock.getpeername()
            t_addr, t_port = target_sock.getpeername()
            print s_addr, ':', s_port, '<', len(data), '>', t_addr, ':', t_port
            hexdump(data)
        return target_sock.send(data)


def switch(sock, target_sock, head_data=''):
    socks_list = [sock, target_sock]
    ret = -1
    while ret:
        r, w, e = select.select(socks_list, [], [])
        for s in r:
            if s is sock:
                ret = forward(sock, target_sock, head_data)
                head_data = ''
            elif s is target_sock:
                ret = forward(target_sock, sock)

    sock.close()
    target_sock.close()


class Proxy(threading.Thread):
    target_addr = ()
    bind_addr = ()

    def __init__(self, sock):
        super(Proxy, self).__init__()
        self.daemon = True
        self.sock = sock
        self.target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target_sock.connect(Proxy.target_addr)

    def run(self):
        try:
            switch(sock=self.sock, target_sock=self.target_sock)
        except Exception as e:
            print_msg(e)
            self.close()

    def close(self):
        self.sock.close()
        self.target_sock.close()


class ReverseProxyServer(threading.Thread):
    bind_addr = None
    reverse_daemon_sock = None
    reverse_sock_queue = Queue(10)
    '''
    TCP -> A:8080 <-> B <-> C:22
                            C:80
                            C:21

    \xff\x00\x00    反向代理守护线程，控制客户端创建新的反向代理通道
    \xff\x01\x00    声明sock是反向流量代理通道
    \xff\x02\x00    通知客户端新建一个反向代理sock
    \xff\x03\x00    重置反向代理守护线程，切换代理端口使用
    \xff\xff\x00    错误
    '''

    class statement(object):
        error = b'\xff\xff\x00'
        daemon_socket = b'\xff\x00\x00'
        reverse_socket = b'\xff\x01\x00'
        new_reverse_socket = b'\xff\x02\x00'
        reset_daemon_socket = b'\xff\x03\x00'

    def __init__(self, sock):
        super(ReverseProxyServer, self).__init__()
        self.daemon = True
        self.reverse_sock = sock
        self.target_sock = None

    def run(self):
        try:
            head_data = self.reverse_sock.recv(3)
            if head_data == '':
                raise Exception('exit')
            elif head_data == ReverseProxyServer.statement.error:
                print_msg(self.reverse_sock.recv(1024))
            elif head_data == ReverseProxyServer.statement.daemon_socket:
                # 守护线程已经存在
                if ReverseProxyServer.reverse_daemon_sock is None:
                    # 反向代理守护线程
                    ReverseProxyServer.reverse_daemon_sock = self.reverse_sock
                else:
                    self.reverse_sock.send(ReverseProxyServer.statement.error + b'reverse_daemon_sock already created')
                    print_msg('reverse_daemon_sock already created')
            elif head_data == ReverseProxyServer.statement.reverse_socket:
                # 将反向代理sock放入队列
                self.reverse_sock_queue.put(self.reverse_sock)
            elif head_data == ReverseProxyServer.statement.reset_daemon_socket:
                if ReverseProxyServer.reverse_daemon_sock:
                    ReverseProxyServer.reverse_daemon_sock.close()
                # 重置反向代理守护线程
                ReverseProxyServer.reverse_daemon_sock = self.reverse_sock
            elif ReverseProxyServer.reverse_daemon_sock is None:
                self.reverse_sock.send(ReverseProxyServer.statement.error + b'reverse_daemon_sock is none')
                raise Exception('reverse_daemon_sock is none')
            else:
                # 通知客户端挂起一个新的反向代理
                ReverseProxyServer.reverse_daemon_sock.sendall(ReverseProxyServer.statement.new_reverse_socket)
                # 获取新创建的反向代理sock
                self.target_sock = self.reverse_sock_queue.get()
                # 第一次交换数据不完整，需要拼接head_data
                switch(sock=self.reverse_sock, target_sock=self.target_sock, head_data=head_data)
        except Exception as e:
            self.close()
            print_msg(e)

    def close(self):
        if self.target_sock:
            self.target_sock.close()
        self.reverse_sock.close()


class ReverseProxyClient(threading.Thread):
    server_addr = None
    target_addr = None

    def __init__(self):
        super(ReverseProxyClient, self).__init__()
        self.daemon = True

        self.reverse_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.reverse_sock.connect(self.server_addr)

        self.target_sock = target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.connect(self.target_addr)

    def run(self):
        try:
            self.reverse_sock.sendall(ReverseProxyServer.statement.reverse_socket)
            switch(sock=self.reverse_sock, target_sock=self.target_sock)
        except Exception as e:
            print_msg(e)
            self.close()

    def close(self):
        self.reverse_sock.close()
        self.target_sock.close()


def server_loop_forever(proxy_handle):
    ps = []
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(proxy_handle.bind_addr)
    server_sock.listen(50)
    try:
        while True:
            sock, addr = server_sock.accept()
            if debug:
                print_msg('Received incoming connection from %s:%d' % (addr[0], addr[1]))
            proxy = proxy_handle(sock=sock)
            proxy.start()
            ps.append(proxy)
    except KeyboardInterrupt:
        server_sock.close()
        for proxy in ps:
            proxy.close()


def reverse_client_loop_forever(client_proxy_handle, statement):
    rss = []
    daemon_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    daemon_sock.connect(client_proxy_handle.server_addr)
    # 通知服务端连接的是守护进程
    daemon_sock.sendall(statement)
    try:
        while True:
            try:
                data = daemon_sock.recv(3)
                if data == '':
                    raise Exception('exit')
                elif data == ReverseProxyServer.statement.error:
                    raise Exception(daemon_sock.recv(buffer_size))
                # 挂起一个反向代理线程
                elif data == ReverseProxyServer.statement.new_reverse_socket:
                    reverse_client_proxy = client_proxy_handle()
                    reverse_client_proxy.start()
                    rss.append(reverse_client_proxy)
                else:
                    print 'unknown ' + data
            except Exception as e:
                print e
                daemon_sock.close()
                for rs in rss:
                    rs.close()
                break
    except KeyboardInterrupt:
        daemon_sock.close()
        for rs in rss:
            rs.close()


def usage():
    project_name = os.path.basename(sys.argv[0])
    print 'lcx v1.00'
    print
    print 'Usage: {} -l 0.0.0.0 -p 8080'.format(project_name)
    print '-l --listen              - listen on [host] for proxy service'
    print '-t --target=ip           - connect proxy server ip'
    print '-p --port                - listen/connect [port]'
    print '-r --reverse             - listen for reverse proxy service'
    print '   --reset             - reset connect target'
    print '   --debug             - print debug massage'
    print
    print
    print 'Examples: '
    print '{} -l 0.0.0.0 -p 8080 -t 192.168.1.1:22'.format(project_name)
    print '{} -l 192.168.1.2 -p 8080 --reverse'.format(project_name)
    print '{} -c 192.168.1.2 -p 8080 -t 192.168.1.1:22'.format(project_name)
    print '{} -c 192.168.1.2 -p 8080 -t 192.168.1.1:22 --reset'.format(project_name)
    print '{} -c 192.168.1.2 -p 8080 -t 192.168.1.1:22 --reset --debug'.format(project_name)
    sys.exit(0)


if __name__ == '__main__':
    opts = []
    _reverse_proxy = False
    _listen = False
    _statement = ReverseProxyServer.statement.daemon_socket
    _bind_host = '127.0.0.1'
    _bind_port = 8080
    _target_host = ''
    _target_port = 0
    if not len(sys.argv[1:]):
        usage()

    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h:l:p:rt:c:',
                                   ['help', 'ip', 'port', 'reverse', 'connect', 'reset', 'debug'])
    except getopt.GetoptError as err:
        print_msg(str(err))
        usage()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-l', '--listen'):
            _listen = True
            _bind_host = a
        elif o in ('-p', '--port'):
            _bind_port = int(a)
        elif o in ('-c', '--connect'):
            _bind_host = a
            _reverse_proxy = True
        elif o in ('-t', '--target'):
            a = a.split(':')
            _target_host = a[0]
            _target_port = int(a[1])
        elif o in ('-r', '--reverse'):
            _reverse_proxy = True
        elif o in ('--reset',):
            _statement = ReverseProxyServer.statement.reset_daemon_socket
            _reverse_proxy = True
        elif o in ('--debug',):
            debug = True
        else:
            assert False, 'Unhandled Option'

    if _reverse_proxy:
        if _listen:
            ReverseProxyServer.bind_addr = (_bind_host, _bind_port)
            server_loop_forever(proxy_handle=ReverseProxyServer)
        else:
            ReverseProxyClient.server_addr = (_bind_host, _bind_port)
            ReverseProxyClient.target_addr = (_target_host, _target_port)
            reverse_client_loop_forever(client_proxy_handle=ReverseProxyClient, statement=_statement)
    else:
        Proxy.bind_addr = (_bind_host, _bind_port)
        Proxy.target_addr = (_target_host, _target_port)
        server_loop_forever(proxy_handle=Proxy)

