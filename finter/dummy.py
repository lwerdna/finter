#!/usr/bin/env python

# a dummy dissector for testing

import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    setLittleEndian()

    while not IsEof(fp) and remaining(fp) >= 15:
        tag(fp, 15, 'chunk', 1)
        tagUint8(fp, 'a', 'comment')
        tagUint16(fp, 'b', 'comment')
        tagUint32(fp, 'c', 'comment')
        tagUint64(fp, 'd', 'comment')

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
