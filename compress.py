#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019/11/29 18:00
# @Author  : a
# @FileName: result.py
# @Software: PyCharm

import tarfile
import bz2

# tar -jxf 
def tarbz2(path, bz_path=None):
    if bz_path is None:
        bz_path = path
    archive = tarfile.open('{}.tar.bz2'.format(bz_path),'w:bz2')
    # archive.debug = 1
    # arcname specifies an alternative name for the file in the archive.
    archive.add(path, '/')  # d:\myfiles contains the files to compress
    archive.close()

