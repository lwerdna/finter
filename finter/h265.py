#!/usr/bin/env python

# References:
# https://github.com/GStreamer/gstreamer/blob/main/subprojects/gst-plugins-bad/gst-libs/gst/codecparsers/gsth265parser.c

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

class H264_NALU_TYPE(Enum):
    H265_NAL_SLICE_TRAIL_N = 0
    H265_NAL_SLICE_TRAIL_R = 1
    H265_NAL_SLICE_TSA_N = 2
    H265_NAL_SLICE_TSA_R = 3
    H265_NAL_SLICE_STSA_N = 4
    H265_NAL_SLICE_STSA_R = 5
    H265_NAL_SLICE_RADL_N = 6
    H265_NAL_SLICE_RADL_R = 7
    H265_NAL_SLICE_RASL_N = 8
    H265_NAL_SLICE_RASL_R = 9
    H265_NAL_SLICE_BLA_W_LP = 16
    H265_NAL_SLICE_BLA_W_RADL = 17
    H265_NAL_SLICE_BLA_N_LP = 18
    H265_NAL_SLICE_IDR_W_RADL = 19
    H265_NAL_SLICE_IDR_N_LP = 20
    H265_NAL_SLICE_CRA_NUT = 21
    H265_NAL_VPS = 32
    H265_NAL_SPS = 33
    H265_NAL_PPS = 34
    H265_NAL_AUD = 35
    H265_NAL_EOS = 36
    H265_NAL_EOB = 37
    H265_NAL_FD = 38
    H265_NAL_PREFIX_SEI = 39
    H265_NAL_SUFFIX_SEI = 40
    
class ForbiddenZeroViolation(Exception):
    def __init__(self):
        super().__init__('')

def tag_nalu(fp, length):
    sample = int.from_bytes(peek(fp, 2), 'big')

    fzb, type_, layer_id, tid = tagBits(fp, \
        ('forbidden_zero_bit', 1),
        ('nal_unit_type', 6),
        ('nuh_layer_id', 6),
        ('nuh_temporal_id_plus1', 3)
    )

    if fzb != 0:
        raise ForbiddenZeroViolation()

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
