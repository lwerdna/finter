#!/usr/bin/env python

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

def tag_rtp(fp, length):
    start = fp.tell()

    flags = tagUint8(fp, 'flags')
    ptype = tagUint8(fp, 'payload_type')
    tagUint16(fp, 'sequence_num')
    tagUint32(fp, 'timestamp')
    tagUint32(fp, 'sync')

    # extensions?
    if flags & 0x10:
        extension_id = tagUint16(fp, 'extension_id')
        extension_len = tagUint16(fp, 'extension_len')
        for i in range(extension_len):
            tag(fp, 4, f'extensions[{i}]')
        payload_length = length - (16 + 4*extension_len)
    else:
        payload_length = length - 12

    # is padding present?
    if flags & 0x20:
        tmp = fp.tell()
        fp.seek(payload_length - 1, io.SEEK_CUR)
        padlen = uint8(fp)
        assert padlen in [1, 2, 3]
        fp.seek(-padlen, io.SEEK_CUR)
        tag(fp, padlen, 'padding')
        payload_length -= padlen
        fp.seek(tmp)
    
    tag(fp, payload_length, 'payload')

    tagFromPosition(fp, start, 'RTP')

    return fp.tell() - start

def tag_rtsp(fp):
    start = fp.tell()

    tagUint8(fp, 'magic')
    tagUint8(fp, 'channel')
    payload_len = tagUint16(fp, 'payload_len')

    if payload_len:
        used = 0
        while used < payload_len:
            used += tag_rtp(fp, payload_len)

    tagFromPosition(fp, start, 'RTSP')

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    setBigEndian()

    while not IsEof(fp):
        tag_rtsp(fp)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
