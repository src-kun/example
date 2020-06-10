#!/usr/bin/python
# -*- coding: utf-8 -*-

# 参考：
#   https://pypi.python.org/pypi/qqwry-py3
#   http://staff.ustc.edu.cn/~ypb/exp/qqwry.pdf
#   https://github.com/out0fmemory/qqwry.dat

import bisect
import struct
import socket


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def int3(data, offset):
    return data[offset] + (data[offset + 1] << 8) + \
           (data[offset + 2] << 16)


def int4(data, offset):
    return data[offset] + (data[offset + 1] << 8) + \
           (data[offset + 2] << 16) + (data[offset + 3] << 24)


class QQwry:

    def __init__(self):
        self.__data = None
        self.index_begin = None
        self.index_end = None
        self.index_count = None

        self.index_array_begin = []
        self.index_array_end = []
        self.index_array_country = []
        self.index_array_province = []

        self.__segments = []

    def load_file(self, filename):
        with open(filename, 'br') as f:
            self.__data = buffer = f.read()

        if len(buffer) < 8:
            raise Exception('%s load failed, file only %d bytes' % (filename, len(buffer)))

        self.index_begin = int4(buffer, 0)
        self.index_end = int4(buffer, 4)
        self.index_count = (self.index_end - self.index_begin) // 7 + 1

        # load segments
        for i in range(0, self.index_count):
            begin_offset = self.index_begin + 7 * i
            ip_begin = int4(self.__data, begin_offset)
            end_offset = int3(self.__data, begin_offset + 4)
            ip_end = int4(self.__data, end_offset)
            country_province = self.__get_country_province(end_offset + 4)

            self.index_array_begin.append(ip_begin)
            self.index_array_end.append(ip_end)
            self.index_array_country.append(country_province[0])
            self.index_array_province.append(country_province[1])
            self.__segments.append((ip_begin, ip_end, country_province))
        print('%s %s bytes, %d segments. with index.' %
              (filename, format(len(buffer), ','), self.index_count)
              )

    def __get_country_province(self, offset: int) -> tuple:
        # mode 0x01, full jump
        mode = self.__data[offset]
        if mode == 1:
            offset = int3(self.__data, offset + 1)
            mode = self.__data[offset]
        # country
        if mode == 2:
            offset_country = int3(self.__data, offset + 1)
            country = self.__data[offset_country:self.__data.index(b'\x00', offset_country)]
            offset += 4
        else:
            country = self.__data[offset:self.__data.index(b'\x00', offset)]
            offset += len(country) + 1

        # province
        if self.__data[offset] == 2:
            offset = int3(self.__data, offset + 1)
        province = self.__data[offset:self.__data.index(b'\x00', offset)]

        return country.decode('gb18030', errors='replace'), province.decode('gb18030', errors='replace')

    def lookup(self, ip_str: str) -> tuple:
        ip = struct.unpack(">I", socket.inet_aton(ip_str))[0]
        pos = bisect.bisect_right(self.index_array_begin, ip) - 1
        if pos == -1:
            raise Exception('ip error %s' % ip)

        if self.index_array_begin[pos] <= ip <= self.index_array_end[pos]:
            return self.index_array_country[pos], self.index_array_province[pos]

    @property
    def is_loaded(self) -> bool:
        return not self.__data

    @property
    def version(self) -> str:
        return '%s%s' % (self.index_array_country[-1], self.index_array_province[-1])

    @property
    def ip_segments(self) -> list:
        return self.__segments

    # TODO 启动时建立国家索引
    def query_segments_by_country(self, country) -> list:
        country_segments = []
        for c in self.index_array_country:
            if country in c:
                index = self.index_array_country.index(c)
                country_segments.append((int2ip(self.index_array_begin[index]), int2ip(self.index_array_end[index])))
        return country_segments

    # TODO 启动时建立拥有者索引
    def query_segments_by_province(self, province):
        province_segments = []
        for p in self.index_array_province:
            if province in p:
                index = self.index_array_province.index(p)
                province_segments.append((int2ip(self.index_array_begin[index]), int2ip(self.index_array_end[index])))
        return province_segments


if __name__ == '__main__':
    import datetime

    fn = '/home/kali/qqwry_lastest.dat'
    q = QQwry()
    access_start = datetime.datetime.now()
    q.load_file(fn)
    access_end = datetime.datetime.now()
    access_delta = (access_end - access_start).seconds * 1000
    print(access_delta)
    print(q.version)

    access_start = datetime.datetime.now()
    print(q.lookup('47.240.93.85'))
    access_end = datetime.datetime.now()
    access_delta = (access_end - access_start).seconds * 1000
    print(access_delta)
    segments = q.query_segments_by_country('香港')
    print(segments)
    segments = q.query_segments_by_province('阿里云')
    print(len(segments))
    # print(int2ip(segments[0]), int2ip(segments[1]))
