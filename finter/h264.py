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
        case 7: return 'Sequence parameter set (non-VCL)'
        case 8: return 'Picture parameter set (non-VCL)'
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
        case 24: return 'Unspecified'
        case 25: return 'Unspecified'
        case 26: return 'Unspecified'
        case 27: return 'Unspecified'
        case 28: return 'Unspecified'
        case 29: return 'Unspecified'
        case 30: return 'Unspecified'
        case 31: return 'Unspecified'
        case 24: return 'stap_a'
        case 28: return 'fu_a'
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

def tag_nalu(fp, length):
    b0 = int.from_bytes(peek(fp, 1), 'big')
    forbidden_zero_bit = b0 >> 7
    nal_ref_idc = (b0 & 0x6) >> 5
    nal_unit_type = b0 & 0x1F

    assert forbidden_zero_bit == 0

    tag(fp, 1, 'byte0', f'nri={nal_ref_idc} type={nal_unit_type}', 1)
    tag(fp, length, 'nalu', '('+nalu_type_to_str(nal_unit_type)+')')

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
