#!/usr/bin/env python

# ffprobe -v error -show_format -show_streams input.mpeg
# https://aeroquartet.com/treasured/mpeg.en.html
# http://dvdnav.mplayerhq.hu/dvdinfo/mpeghdrs.html
# https://github.com/kynesim/tstools/blob/master/ps.c
# 

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

from . import h264

def stream_id_to_string(code):
    if code == 0: return 'picture'
    elif 1 <= code <= 0xaf: return 'slice'
    elif code in [0xb0, 0xb1]: return 'reserved'
    elif code == 0xb2: return 'user data'
    elif code == 0xb3: return 'sequence header'
    elif code == 0xb4: return 'sequence error'
    elif code == 0xb5: return 'extension'
    elif code == 0xb6: return 'reserved'
    elif code == 0xb7: return 'sequence end'
    elif code == 0xb8: return 'group of pictures'

    # H.222 Program stream specific codes
    elif code == 0xb9: return 'program end'
    elif code == 0xba: return 'pack header'
    elif code == 0xbb: return 'system header'
    elif code == 0xbc: return 'program stream map'

    # Other "simple" values from H.222 Table 2-18, page 32
    elif code == 0xbd: return 'private stream 1'
    elif code == 0xbe: return 'padding stream'
    elif code == 0xbf: return 'private stream 2'
    elif 0xc0 <= code <= 0xdf: return 'mpeg-1 or mpeg-2 audio stream'
    elif 0xe0 <= code <= 0xef: return 'mpeg-1 or mpeg-2 video stream'
    elif code == 0xf0: return 'ecm stream'
    elif code == 0xf1: return 'emm stream'
    elif code == 0xf2: return 'ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Annex A or ISO/IEC 13818-6_DSMCC_stream'
    elif code == 0xf3: return 'ISO/IEC_13522_stream'
    elif code == 0xf4: return 'ITU-T Rec. H.222.1 type A'
    elif code == 0xf5: return 'ITU-T Rec. H.222.1 type B'
    elif code == 0xf6: return 'ITU-T Rec. H.222.1 type C'
    elif code == 0xf7: return 'ITU-T Rec. H.222.1 type D'
    elif code == 0xf8: return 'ITU-T Rec. H.222.1 type E'
    elif code == 0xf9: return 'ancillary stream'

    elif 0xaf <= code <= 0xfe: return 'reserved'
    elif code == 0xff: return 'program stream directory'
    else: return 'unknown'

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    setBigEndian()

    sample = int.from_bytes(peek(fp, 4), 'big')
    prefix = sample >> 8
    stream_id = sample & 0xff
    if prefix == 1 and stream_id_to_string(stream_id) == 'unknown':
        return

    if stream_id == 0xba:
        mark = fp.tell()

        tag(fp, 3, 'packet_start_code_prefix')
        tagUint8(fp, 'map_stream_id')

        # consume byte [4, 5, 6, 7, 8, 9]
        bs = BitStream(peek(fp, 6))
        assert bs.stream(2) == 1
        scr = bs.stream(3)
        assert bs.stream(1) == 1
        scr = (scr << 15) | bs.stream(15)
        assert bs.stream(1) == 1
        scr = (scr << 15) | bs.stream(15)
        assert bs.stream(1) == 1
        scr_ext = bs.stream(9)
        assert bs.stream(1) == 1
        
        tag(fp, 6, 'anon', f'scr={scr:X}h scr_ext={scr_ext:X}h')
    
        # consume bytes [10, 11, 12, 13]
        bs = BitStream(peek(fp, 4))
        program_mux_rate = bs.stream(22)
        assert bs.stream(2) == 3
        reserved = bs.stream(5)
        pack_stuffing_length = bs.stream(3)

        tag(fp, 4, 'anon', 'program_mux_rate=%Xh pack_stuffing_length=%Xh' % \
            (program_mux_rate, pack_stuffing_length))

        if pack_stuffing_length:
            tag(fp, pack_stuffing_length, 'stuffing')

        tagFromPosition(fp, mark, 'pack_header')

    # iso13818-1.pdf 2.5.4.1
    elif stream_id == 0xbc:
        mark = fp.tell()

        tag(fp, 3, 'packet_start_code_prefix')
        tagUint8(fp, 'map_stream_id')

        tag(fp, 2, 'program_stream_map_length')

        current_next_indicator, reserved, program_stream_map_version = \
            bitsplit(peek(fp, 1), 1, 2, 5)
        tagUint8(fp, 'current_next_indicator=%Xh program_stream_map_version=%Xh' % \
            (current_next_indicator, program_stream_map_version))
        
        tagFromPosition(fp, mark, 'program stream map')

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
