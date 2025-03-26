#!/usr/bin/env python

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

from . import h264

def tag_rtp(fp, length, channel=None):
    start = fp.tell()

    # RTP HEADER (no extension)
    # 00: flags         (1)
    # 01: payload type  (1)
    # 02: sequence num  (2)
    # 04: timestamp     (4)
    # 08: synch         (4)
    # 12: payload       (?)
    #
    # RTP HEADER (with extensions)
    # 00: flags         (1) (flags & 0x10)
    # 01: payload type  (1)
    # 02: sequence num  (2)
    # 04: timestamp     (4)
    # 08: synch         (4)
    # 12: extension_id  (2)
    # 14: extension_len (2)
    # 16: extensions    (4*extension_len)
    # ??: payload       (?)

    tmp = uint8(fp, peek=True)
    ver = tmp >> 6
    P = (tmp >> 5) & 1
    X = (tmp >> 4) & 1
    CC = tmp & 0xf
    tagUint8(fp, 'b0', f'ver={ver} pad={P} ext={X} CC={CC}')

    tmp = uint8(fp, peek=True)
    M = tmp >> 7
    payload_type = tmp & 0x7f
    tagUint8(fp, 'b1', f'M={M} payload_type={payload_type}')
    tagUint16(fp, 'sequence_num')
    tagUint32(fp, 'timestamp')
    tagUint32(fp, 'sync')

    # extensions?
    if X:
        extension_id = tagUint16(fp, 'extension_id')
        extension_len = tagUint16(fp, 'extension_len')
        for i in range(extension_len):
            tag(fp, 4, f'extensions[{i}]')
        payload_length = length - (16 + 4*extension_len)
    else:
        payload_length = length - 12

    # is padding present?
    padlen = 0
    if P:
        tmp = fp.tell()
        fp.seek(payload_length - 1, io.SEEK_CUR)
        padlen = uint8(fp)
        assert padlen in [1, 2, 3]
        payload_length -= padlen
        fp.seek(tmp)

    tag(fp, payload_length, 'payload', '', peek=True)
    h264.tag_nalu(fp, payload_length)

    if padlen:
        tag(fp, padlen, 'padding')

    tagFromPosition(fp, start, 'RTP')

    return fp.tell() - start

def tag_rtsp(fp):
    start = fp.tell()

    if (magic := tagUint8(fp, 'magic')) != 0x24:
        raise Exception(f'got magic byte: 0x{magic:X} (expected 0x24)')
    channel = tagUint8(fp, 'channel')
    payload_len = tagUint16(fp, 'payload_len')

    if payload_len:
        used = 0
        while used < payload_len:
            used += tag_rtp(fp, payload_len, channel)

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
