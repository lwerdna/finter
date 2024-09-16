#!/usr/bin/env python

# https://stackoverflow.com/questions/24884827/possible-locations-for-sequence-picture-parameter-sets-for-h-264-stream

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

def nalu_type_to_str(x):
    match x:
        case 0: return 'Unspecified (non-VCL)'
        case 1: return 'Coded slice of a non-IDR picture (VCL)'
        case 2: return 'Coded slice data partition A (VCL)'
        case 3: return 'Coded slice data partition B (VCL)'
        case 4: return 'Coded slice data partition C (VCL)'
        case 5: return 'Coded slice of an IDR picture (VCL)'
        case 6: return 'Supplemental enhancement information (SEI) (non-VCL)'
        case 7: return 'Sequence parameter set (SPS) (non-VCL)'
        case 8: return 'Picture parameter set (PPS) (non-VCL)'
        case 9: return 'Access unit delimiter (non-VCL)'
        case 10: return 'End of sequence (non-VCL)'
        case 11: return 'End of stream (non-VCL)'
        case 12: return 'Filler data (non-VCL)'
        case 13: return 'Sequence parameter set extension (non-VCL)'
        case 14: return 'Prefix NAL unit (non-VCL)'
        case 15: return 'Subset sequence parameter set (non-VCL)'
        case 16: return 'Depth parameter set (non-VCL)'
        case 17: return 'Reserved'
        case 18: return 'Reserved'
        case 19: return 'Coded slice of an auxiliary coded picture without partitioning (non-VCL)'
        case 20: return 'Coded slice extension (non-VCL)'
        case 21: return 'Coded slice extension for depth view components (non-VCL)'
        case 22: return 'Reserved'
        case 23: return 'Reserved'
        case 24: return 'STAP-A'
        case 25: return 'STAP-B'
        case 26: return 'MTAP16'
        case 27: return 'MTAP24'
        case 28: return 'FU-A'
        case 29: return 'FU-B'
        case 30: return 'reserved'
        case 31: return 'reserved'
        case _: return '(unknown)'

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

def tag_nalu_fu_a(fp, length):
    b0 = int.from_bytes(tag(fp, 1, 'fu_indicator', ''), 'big')
    b1 = int.from_bytes(peek(fp, 1), 'big')
    # +---------------+
    # |0|1|2|3|4|5|6|7|
    # +-+-+-+-+-+-+-+-+
    # |S|E|R|  Type   |
    # +---------------+
    s = bool(b1 & 0x80)
    e = bool(b1 & 0x40)
    r = bool(b1 & 0x20)
    ftype = b1 & 0x1F
    comms = []
    comms.append('S=1 (start)' if s else 'S=0')
    comms.append('E=1 (end)' if e else 'E=0')
    assert r == 0
    comms.append('R=0')
    comms.append(f'type=%d (%s)' % (ftype, nalu_type_to_str(ftype)))
    tag(fp, 1, 'fu_header %s' % ' '.join(comms))

    #
    tag(fp, length-2, 'fu_payload')

def tag_nalu(fp, length):
    sample = peek(fp, 2)

    # +---------------+
    # |0|1|2|3|4|5|6|7|
    # +-+-+-+-+-+-+-+-+
    # |F|NRI|  Type   |
    # +---------------+
    forbidden_zero_bit = sample[0] >> 7
    assert forbidden_zero_bit == 0
    nal_ref_nri = (sample[0] & 0x6) >> 5
    nal_unit_type = sample[0] & 0x1F

    if nal_unit_type == 28:
        tag_nalu_fu_a(fp, length)
    else:
        tag(fp, 1, 'byte0', f'nri={nal_ref_nri} type={nal_unit_type}', 1)

        comment = '(%s), %d (0x%X) bytes' % \
            (nalu_type_to_str(nal_unit_type), length, length)

        tag(fp, length, 'NALU', comment)

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    setLittleEndian()

    while not IsEof(fp):
        sclen, nalulen = seek_nalu(fp)
        tag(fp, sclen, 'start code')
        tag_nalu(fp, nalulen)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
