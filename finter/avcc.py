#!/usr/bin/env python

import os
import re
import sys

from .helpers import *

from . import h264

def analyze(fp):
    setBigEndian()

    while not IsEof(fp):
        # 4 bytes for each length is most common, but really this could be
        # 1,2,3 or 4 and is specified in the avcc extradata
        length = tagUint32(fp, 'length')
        h264.tag_nalu(fp, length)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
