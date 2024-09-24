#!/usr/bin/env python

import sys
from enum import Enum

from . import tzsp
from .helpers import *

###############################################################################
# "main"
###############################################################################

def analyze(fp, length=None):
    endian = setBigEndian()

    start = fp.tell()

    tagUint16(fp, 'SrcPort', lambda x: f'({x:d})')
    tagUint16(fp, 'DstPort', lambda x: f'({x:d})')
    tagUint16(fp, 'Length', lambda x: f'({x:d})')
    tagUint16(fp, 'Checksum')

    sample = peek(fp, 5)
    # guess TZSP ver=1 type=0 (rx'd pkt) proto=Ether no tags
    if sample == b'\x01\x00\x00\x01\x01':
        tzsp.analyze(fp, length-8)
    else:
        tag(fp, length-8, 'payload')

    tagFromPosition(fp, start, 'UDP')

    setEndian(endian)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
