#!/usr/bin/python3  
# -*- coding: utf-8 -*-  

import tarfile
import bz2

def tarbz2(source, target=None):
    if target is None:
        target = '%s.tar.bz2' % source
    archive = tarfile.open(target, 'w:bz2')
    # archive.debug = 1
    # arcname specifies an alternative name for the file in the archive.
    archive.add(source, source.split('/')[-1]) 
    archive.close()
    return target
