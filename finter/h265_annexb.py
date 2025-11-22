#!/usr/bin/env python

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

from . import h265

def find_all(haystack, needle):
    i = -1
    result = []
    while True:
        i = haystack.find(needle, i+1)
        if i == -1: break
        result.append(i)
    return result

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    setLittleEndian()

    data = fp.read()

    # does this file start with a start code (h265 delimeter)?
    code3 = b'\x00\x00\x01'
    code4 = b'\x00\x00\x00\x01'
    if not (data.startswith(code3) or data.startswith(code4)):
        return

    # precompute location of all start codes
    #
    # |code|nalu|code|nalu|...|code|nalu|
    # ^         ^             ^
    start4 = find_all(data, code4)
    start3 = [x for x in find_all(data, code3) if not x in set([a+1 for a in start4])]
    starts = sorted(start4 + start3)

    # |code|nalu|code|nalu|...|code|nalu|
    # ^         ^
    # a         b
    for a, b in zip(starts, starts[1:] + [len(data)]):
        fp.seek(a)
        if peek(fp, 3) == code3:
            tag(fp, 3, 'start code')
            len_nalu = b - a - 3
        else:
            tag(fp, 4, 'start code')
            len_nalu = b - a - 4

        try:
            h265.tag_nalu(fp, len_nalu)
        except h265.ForbiddenZeroViolation:
            tag(fp, len_nalu, 'malformed nalu')

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
