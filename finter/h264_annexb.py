#!/usr/bin/env python

# https://stackoverflow.com/questions/24884827/possible-locations-for-sequence-picture-parameter-sets-for-h-264-stream

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

from . import h264

# assumes fp is positioned at a start code
# returns (start_code_len, nalu_len)
# very inefficient, does large reads to the end of the file from each start code
def seek_nalu(fp):
    home = fp.tell()

    buffer = fp.read()

    # read start code
    sclen = None
    if buffer[0:3] == b'\x00\x00\x01':
        sclen = 3
    elif buffer[0:4] ==  b'\x00\x00\x00\x01':
        sclen = 4
    if sclen is None:
        raise Exception(f'expected start code at offset 0x{home:X}')
   
    # find next start code
    end = buffer.find(b'\x00\x00\x01', sclen)
    if end == -1:
        nalu_len = len(buffer) - sclen
    else:
        if buffer[end-1] == 0:
            end -= 1
        nalu_len = end - sclen

    # back home
    fp.seek(home, io.SEEK_SET)
    return (sclen, nalu_len)

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    setLittleEndian()

    while not IsEof(fp):
        sclen, nalulen = seek_nalu(fp)
        tag(fp, sclen, 'start code')
        h264.tag_nalu(fp, nalulen)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
