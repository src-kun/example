#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
参考：
    SOCKS Protocol Version 5:
        https://www.ietf.org/rfc/rfc1928.txt
"""
import getopt
import os
import select
import socket
import sys
import time
from Queue import Queue
from threading import Thread

debug = False
buffer_size = 1024 * 2
proxy_ip_pool = set()
max_reverse_client_thread = 10
reverse_socks_queue = Queue(20)


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


def forward(sock, target_sock):
    data = sock.recv(buffer_size)
    if data:
        if debug:
            s_addr, s_port = sock.getpeername()
            t_addr, t_port = target_sock.getpeername()
            print s_addr, ':', s_port, '<', len(data), '>', t_addr, ':', t_port
            hexdump(data)
        return target_sock.send(data)


def switch(sock, target_sock):
    socks_list = [sock, target_sock]
    ret = -1
    while ret:
        r, w, e = select.select(socks_list, [], [])
        for s in r:
            if s is sock:
                ret = forward(sock, target_sock)
            elif s is target_sock:
                ret = forward(target_sock, sock)

    sock.close()
    target_sock.close()


class auth(object):
    whether = True
    user = 'oleadmin'
    password = '3.14@0src'

    @staticmethod
    def verify(user, password):
        if user == auth.user and auth.password == password:
            return True


'''
The SOCKS request is formed as follows:

       +----+-----+-------+------+----------+----------+
       |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
       +----+-----+-------+------+----------+----------+
       | 1  |  1  | X'00' |  1   | Variable |    2     |
       +----+-----+-------+------+----------+----------+

    Where:

         o  VER    protocol version: X'05'
         o  CMD
            o  CONNECT X'01'
            o  BIND X'02'
            o  UDP ASSOCIATE X'03'
         o  RSV    RESERVED
         o  ATYP   address type of following address
            o  IP V4 address: X'01'
            o  DOMAINNAME: X'03'
            o  IP V6 address: X'04'
         o  DST.ADDR       desired destination address
         o  DST.PORT desired destination port in network octet
            order
'''


def parse_request(data):
    dsp_port = 0
    dsp_addr = ''

    CMD = ord(data[1:2])
    ATYP = ord(data[3:4])
    if CMD == 0x01:
        if ATYP == 03:
            addr_len = ord(data[4:5])
            dsp_port = 256 * ord(data[5 + addr_len:5 + addr_len + 1]) + ord(data[1 + 5 + addr_len:5 + addr_len + 2])
            dsp_addr = socket.gethostbyname(data[5:5 + addr_len])
        elif ATYP == 01:
            if data.count('.') == 4:
                addr_len = ord(data[4:5])
                dsp_addr = data[5:5 + addr_len]
                dsp_port = 256 * ord(data[5 + addr_len:5 + addr_len + 1]) + ord(
                    data[5 + addr_len + 1:5 + addr_len + 2])
            else:
                dsp_addr = data[4:8]
                DspAddrr = ''
                for i in dsp_addr:
                    DspAddrr += str(ord(i)) + '.'
                dsp_addr = DspAddrr[:-1]
                dsp_port = 256 * ord(data[4 + 4:4 + 4 + 1]) + ord(data[4 + 4 + 1:4 + 4 + 2])
        return dsp_addr, dsp_port
    else:
        print_msg('error')


'''
Referer:
    http://www.faqs.org/rfcs/rfc1929.html
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
+----+------+----------+------+----------+
'''


def parse_authentication(data):
    ver = data[0]
    user_len = ord(data[1])
    user = data[2:2 + user_len].decode('utf-8')
    pass_len = ord(data[2 + user_len:2 + user_len + 1])
    password = data[2 + user_len + 1:2 + user_len + 1 + pass_len]
    return ver, user, password


'''
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

'''


def parse_identifier(data):
    VER = data[0]
    NMETHODS = data[1]
    METHODS = data[2]
    return VER, NMETHODS, data[2]


class Socks5(Thread):
    bind_addr = ()

    def __init__(self, sock):
        super(Socks5, self).__init__()
        self.daemon = True
        self.sock = sock
        self.dsp_addr = None
        self.dsp_port = None
        self.target_sock = None

    def identifier(self):
        data = self.sock.recv(1024)
        if data:
            return parse_identifier(data)
        else:
            self.sock.close()
        return None, None, None

    def authentication(self):
        '''
         +----+--------+
         |VER | METHOD |
         +----+--------+
         | 1  |   1    |
         +----+--------+
         If the selected METHOD is X'FF', none of the methods listed by the
            client are acceptable, and the client MUST close the connection.

         The values currently defined for METHOD are:

               o  X'00' NO AUTHENTICATION REQUIRED
               o  X'01' GSSAPI
               o  X'02' USERNAME/PASSWORD
               o  X'03' to X'7F' IANA ASSIGNED
               o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
               o  X'FF' NO ACCEPTABLE METHODS

         The server verifies the supplied UNAME and PASSWD, and sends the
         following response:

         +----+--------+
         |VER | STATUS |
         +----+--------+
         | 1  |   1    |
         +----+--------+

         A STATUS field of X'00' indicates success. If the server returns a
         `failure' (STATUS value other than X'00') status, it MUST close the
         connection.
         '''
        if auth.whether:
            self.sock.sendall('\x05\x02')
            data = self.sock.recv(1024)
            ver, user, password = parse_authentication(data)
            if auth.verify(user, password):
                self.sock.sendall('\x05\x00')
            else:
                self.sock.sendall('\x05\xff')
                return False
        else:
            self.sock.sendall('\x05\x00')
        return True

    def request(self):
        data = self.sock.recv(1024)
        self.dsp_addr, self.dsp_port = parse_request(data)

    '''
            The SOCKS request information is sent by the client as soon as it has
       established a connection to the SOCKS server, and completed the
       authentication negotiations.  The server evaluates the request, and
       returns a reply formed as follows:

            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+

         Where:

              o  VER    protocol version: X'05'
              o  REP    Reply field:
                 o  X'00' succeeded
                 o  X'01' general SOCKS server failure
                 o  X'02' connection not allowed by ruleset
                 o  X'03' Network unreachable
                 o  X'04' Host unreachable
                 o  X'05' Connection refused
                 o  X'06' TTL expired
                 o  X'07' Command not supported
                 o  X'08' Address type not supported
                 o  X'09' to X'FF' unassigned
              o  RSV    RESERVED
              o  ATYP   address type of following address
                 o  IP V4 address: X'01'
                 o  DOMAINNAME: X'03'
                 o  IP V6 address: X'04'
              o  BND.ADDR       server bound address
              o  BND.PORT       server bound port in network octet order
    '''

    def reply(self):
        self.sock.send('\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

    def run(self):
        try:
            VER, NMETHODS, METHODS = self.identifier()
            if VER == b'\x05':
                self.authentication()
                self.request()
                self.reply()
                self.target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.target_sock.connect((self.dsp_addr, self.dsp_port))
                switch(sock=self.sock, target_sock=self.target_sock)
            else:
                self.close()
                print_msg('协议不支持')
        except Exception as e:
            print_msg(e)
            self.close()

    def close(self):
        if self.target_sock:
            self.target_sock.close()
        self.sock.close()


class ReverseSocks5Server(Socks5):

    def __init__(self, sock):
        super(ReverseSocks5Server, self).__init__(sock)
        self.daemon = True

    def run(self):
        try:
            VER, NMETHODS, METHODS = self.identifier()
            if VER == '\x05':
                self.authentication()
                self.target_sock = reverse_socks_queue.get()
                switch(sock=self.sock, target_sock=self.target_sock)
            elif VER == '\xff':
                sock_host, sock_port = self.sock.getpeername()
                proxy_ip_pool.add(sock_host)
                reverse_socks_queue.put(self.sock)
            else:
                self.sock.close()
        except Exception as e:
            print_msg(e)
            self.close()


class ReverseSocks5Client(Socks5):

    def __init__(self):
        super(ReverseSocks5Client, self).__init__(sock=None)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(Socks5.bind_addr)

    def hello(self):
        self.sock.send('\xff\x00\x00')

    def run(self):
        try:
            self.reply()

            self.target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.target_sock.connect((self.dsp_addr, self.dsp_port))

            switch(sock=self.sock, target_sock=self.target_sock)
        except Exception as e:
            print_msg(e)
            self.close()


def server_loop_forever(socks5_handle):
    rs5s = []
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(socks5_handle.bind_addr)
    server.listen(100)
    try:
        while True:
            sock, addr = server.accept()
            socks5_client = socks5_handle(sock)
            socks5_client.start()
            rs5s.append(socks5_client)
    except KeyboardInterrupt:
        server.close()
        for rs5 in rs5s:
            rs5.close()


def reverse_client_loop_forever():
    scs = []
    try:
        while True:
            try:
                socks_client = ReverseSocks5Client()
                socks_client.hello()
                socks_client.request()
                socks_client.start()
                scs.append(socks_client)
            except Exception as e:
                print_msg(e)
    except KeyboardInterrupt:
        for sc in scs:
            sc.close()


def usage():
    project_name = os.path.basename(sys.argv[0])
    print 'Socks5 v1.00'
    print
    print 'Usage: {} -l 0.0.0.0 -p 8080'.format(project_name)
    print '-l --listen              - listen on [host] for socks5 service'
    print '-c --connect             - connect socks5 server'
    print '-p --port                - listen on [port]'
    print '-r --reverse             - listen for reverse socks5 service'
    print
    print
    print 'Examples: '
    print '{} -l 0.0.0.0 -p 8080'.format(project_name)
    print '{} -l 0.0.0.0 -p 8080 --reverse'.format(project_name)
    print '{} -c 192.168.1.1 -p 8080'.format(project_name)
    sys.exit(0)


def main():
    global debug
    opts = []
    host = '0.0.0.0'
    port = 8080
    reverse_socks5 = False
    listen = False

    if not len(sys.argv[1:]):
        usage()

    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h:l:p:rc:',
                                   ['help', 'ip', 'port', 'reverse', 'connect', 'debug'])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-l', '--listen'):
            listen = True
            host = a
        elif o in ('-c', '--connect'):
            host = a
        elif o in ('-p', '--port'):
            port = int(a)
        elif o in ('-r', '--reverse'):
            reverse_socks5 = True
        elif o in ('--debug',):
            debug = True
        else:
            assert False, 'Unhandled Option'

    Socks5.bind_addr = (host, port)
    if listen:
        proxy_handle = ReverseSocks5Server if reverse_socks5 else Socks5
        server_loop_forever(proxy_handle)
    else:
        ts = []
        # 开启多个线程等待数据
        for i in range(0, max_reverse_client_thread):
            t = Thread(target=reverse_client_loop_forever)
            t.setDaemon(True)
            t.start()
            ts.append(t)

        while True:
            time.sleep(10)


if __name__ == '__main__':
    main()
