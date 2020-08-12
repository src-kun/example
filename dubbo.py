#!/usr/bin/python3
# -*- coding: utf-8 -*
import json
import socket

host = ''
port = 20880


def invoke(interface: str, *args, **kwargs):
    cmdline = 'invoke ' + interface
    params = '('
    if args:
        params += '%s,' * len(args)
        params = params % args
    if kwargs:
        params += json.dumps(kwargs)
    cmdline += params + ')\n'
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((host, port))
    c.sendall(cmdline.encode())
    # dubbo 默认编码是gbk
    ret = c.recv(4096).decode('GBK', errors='ignore')
    c.close()
    return ret


# 传递普通参数
invoke('com.xxx.api.xxfun', 'param1', 'params')

# 传递对象
invoke('com.xxx.api.xxfun', **{'class': 'com.xxx.dubbo.bean.xxx', 'num': 1, 'name': 'dave'})

# 对象嵌套
invoke('com.xxx.api.xxfun',
       **{'object': {'class': 'com.xxxx.dubbo.bean.xxx', 'num': 1, 'name': 'dave'}, 'id': 2,
          'mark': 'test', 'class': 'com.xxxx.dubbo.service.xxx'})

# 混合调用
invoke('com.xxx.api.xxfun', 'param1', 'params',
       **{'class': 'com.xxx.dubbo.bean.xxx', 'num': 1, 'name': 'dave'})
