#!/usr/bin/env python

# https://stackoverflow.com/questions/24884827/possible-locations-for-sequence-picture-parameter-sets-for-h-264-stream

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

from . import h264

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    setLittleEndian()

    code3 = b'\x00\x00\x01'
    code4 = b'\x00\x00\x00\x01'

    # does this file start with a start code (h264 delimeter)?
    sample = peek(fp, 4)
    if sample == code3:
        code = code3
    elif sample == code4:
        code = code4
    else:
        return

    # precompute location of all start codes
    #
    # |code|nalu|code|nalu|...|code|nalu|
    # ^         ^             ^
    data = fp.read()
    start_locs = []
    i = 0
    while True:
        if (i := data.find(code, i)) == -1:
            break
        start_locs.append(i)
        i += len(code)

    # |code|nalu|code|nalu|...|code|nalu|
    # ^         ^
    # a         b
    for a, b in zip(start_locs, start_locs[1:] + [len(data)]):
        fp.seek(a)
        tag(fp, len(code), 'start code')
        len_nalu = b - (a + len(code))
        h264.tag_nalu(fp, len_nalu)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
