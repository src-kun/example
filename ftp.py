#!/usr/bin/python3
# -*- coding: utf-8 -*-

from ftplib import FTP

if __name__ == "__main__":
    ftp = FTP()
    # 打开调试级别2，显示详细信息
    ftp.set_debuglevel(2)
    ftp.connect('127.0.0.1', 8021)
    ftp.login('test', 'test@12#')

    # download
    fp = open('/tmp/tmp/download.sh', 'wb')
    ftp.retrbinary('RETR 6dcc56cddc09fc984cf4dca502e388c7-test.sh', fp.write, 1024)
    ftp.set_debuglevel(0)  # 参数为0，关闭调试模式

    # upload
    bufsize = 1024
    fp = open('/tmp/tmp/test.sh', 'rb')
    ftp.storbinary('STOR /tmp/upload.sh', fp, bufsize)
    ftp.set_debuglevel(0)
    fp.close()
