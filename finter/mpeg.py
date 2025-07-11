#!/usr/bin/env python

# program stream is composed of elementary streams like video, audio, subtitles, etc.

# ffmpeg -loglevel debug -i input.mpeg -f null -
# ffprobe -show_streams -show_packets -show_frames -bitexact input.mpeg
# ffprobe -v error -show_format -show_streams input.mpeg
# https://aeroquartet.com/treasured/mpeg.en.html
# http://dvdnav.mplayerhq.hu/dvdinfo/mpeghdrs.html
# https://github.com/kynesim/tstools/blob/master/ps.c
# https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-mpeg-descriptor.c

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

from . import h264

# NOTE: stream id is different than stream type
def stream_id_to_string(id_):
    if id_ == 0: return 'picture'
    elif 1 <= id_ <= 0xaf: return 'slice'
    elif id_ in [0xb0, 0xb1]: return 'reserved'
    elif id_ == 0xb2: return 'user data'
    elif id_ == 0xb3: return 'sequence header'
    elif id_ == 0xb4: return 'sequence error'
    elif id_ == 0xb5: return 'extension'
    elif id_ == 0xb6: return 'reserved'
    elif id_ == 0xb7: return 'sequence end'
    elif id_ == 0xb8: return 'group of pictures'

    # H.222 Program stream specific id_s
    elif id_ == 0xb9: return 'program end'
    elif id_ == 0xba: return 'pack header'
    elif id_ == 0xbb: return 'system header'
    elif id_ == 0xbc: return 'program stream map'

    # Other "simple" values from H.222 Table 2-18, page 32
    elif id_ == 0xbd: return 'private stream 1'
    elif id_ == 0xbe: return 'padding stream'
    elif id_ == 0xbf: return 'private stream 2'
    elif 0xc0 <= id_ <= 0xdf: return 'mpeg-1 or mpeg-2 audio stream'
    elif 0xe0 <= id_ <= 0xef: return 'mpeg-1 or mpeg-2 video stream'
    elif id_ == 0xf0: return 'ecm stream'
    elif id_ == 0xf1: return 'emm stream'
    elif id_ == 0xf2: return 'ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Annex A or ISO/IEC 13818-6_DSMCC_stream'
    elif id_ == 0xf3: return 'ISO/IEC_13522_stream'
    elif id_ == 0xf4: return 'ITU-T Rec. H.222.1 type A'
    elif id_ == 0xf5: return 'ITU-T Rec. H.222.1 type B'
    elif id_ == 0xf6: return 'ITU-T Rec. H.222.1 type C'
    elif id_ == 0xf7: return 'ITU-T Rec. H.222.1 type D'
    elif id_ == 0xf8: return 'ITU-T Rec. H.222.1 type E'
    elif id_ == 0xf9: return 'ancillary stream'

    elif 0xaf <= id_ <= 0xfe: return 'reserved'
    elif id_ == 0xff: return 'program stream directory'
    else: return 'unknown'

def stream_type_to_string(type_):
    stream_type_map = {
        0x00: "Reserved",
        0x01: "MPEG-1 Video",
        0x02: "MPEG-2 Video",
        0x03: "MPEG-1 Audio",
        0x04: "MPEG-2 Audio",
        0x05: "Private Sections",
        0x06: "PES packets containing private data",
        0x0F: "AAC Audio (MPEG-2 Part 7)",
        0x10: "MPEG-4 Video",
        0x11: "MPEG-4 LATM AAC Audio",
        0x1B: "H.264 / AVC Video",
        0x24: "H.265 / HEVC Video",
        0x81: "AC-3 Audio (non-standard but widely used)",
        0xBD: "Private Stream 1",
        0xBE: "Padding Stream",
        0xC0: "MPEG-1/MPEG-2 Audio Stream (ID range start)",
        0xE0: "MPEG-1/MPEG-2 Video Stream (ID range start)"
    }

    return stream_type_map.get(type_, "unknown")

def program_elem_descr_tag_to_string(tag):
    descriptor_table = {
        0x00: "Reserved",
        0x01: "Forbidden",
        0x02: "Video stream descriptor",
        0x03: "Audio stream descriptor",
        0x04: "Hierarchy descriptor",
        0x05: "Registration descriptor",
        0x06: "Data stream alignment descriptor",
        0x07: "Target background grid descriptor",
        0x08: "Video window descriptor",
        0x09: "CA (Conditional Access) descriptor",
        0x0A: "ISO 639 language descriptor",
        0x0B: "System clock descriptor",
        0x0C: "Multiplex buffer utilization descriptor",
        0x0D: "Copyright descriptor",
        0x0E: "Maximum bitrate descriptor",
        0x0F: "Private data indicator descriptor",
        0x10: "Smoothing buffer descriptor",
        0x11: "STD descriptor",
        0x12: "IBP descriptor",
        0x1B: "MPEG-4 video descriptor",
        0x1C: "MPEG-4 audio descriptor",
        0x1D: "IOD descriptor",
        0x1E: "SL descriptor",
        0x1F: "FMC descriptor",
        0x20: "External ES ID descriptor",
        0x21: "MuxCode descriptor",
        0x22: "FmxBufferSize descriptor",
        0x23: "MultiplexBuffer descriptor",
        0x24: "Content labeling descriptor",
        0x28: "AVC video descriptor",  # Common in DVB
    }

    # Reserved for ISO/IEC use
    if 0x25 <= tag <= 0x3F:
        return "Reserved (ISO/IEC use)"

    # Private use
    if 0x40 <= tag <= 0xFF:
        return "Private use (vendor-defined)"

    return descriptor_table.get(tag, "unknown")

def descriptor_tag_to_string(tag):
    descriptor_tags = {
        0x02: "Video stream descriptor",
        0x03: "Audio stream descriptor",
        0x04: "Hierarchy descriptor",
        0x05: "Registration descriptor",
        0x06: "Data stream alignment descriptor",
        0x07: "Target background grid descriptor",
        0x08: "Video window descriptor",
        0x09: "Conditional access (CA) descriptor",
        0x0A: "ISO 639 language descriptor",
        0x0B: "System clock descriptor",
        0x0C: "Multiplex buffer utilization descriptor",
        0x0D: "Copyright descriptor",
        0x0E: "Maximum bitrate descriptor",
        0x0F: "Private data indicator descriptor",
        0x10: "Smoothing buffer descriptor",
        0x11: "STD descriptor",
        0x12: "IBP descriptor",
        0x1B: "MPEG-4 video descriptor",
        0x1C: "MPEG-4 audio descriptor",
        0x1D: "IOD descriptor",
        0x1E: "SL descriptor",
        0x1F: "FMC descriptor",
        0x20: "External ES ID descriptor",
        0x21: "MuxCode descriptor",
        0x22: "FmxBufferSize descriptor",
        0x23: "MultiplexBuffer descriptor",
        0x24: "Content labeling descriptor",
        0x25: "Metadata descriptor",
        0x28: "AVC video descriptor (H.264)",
        0x2A: "AVC timing and HRD descriptor",
        0x2F: "Extension descriptor",
    }

    if 0x40 <= tag <= 0xFF:
        return "Private use"

    return descriptor_tags.get(tag, 'unknown')

def tag_picture_header(fp):
    start = fp.tell()

    tag_stream_header(fp)

    frame_type = (peek(fp, 2)[1] >> 3) & 7

    #tagBits(fp, \
    #    ('temp_seq_num', 10),
    #    ('frame_type', 3),
    #    ('vbv_delay', 16)
    #
    tag(fp, 4, 'data')

    tagFromPosition(fp, start, '', 'picture header')


def tag_slice_header(fp):
    start = fp.tell()

    tag_stream_header(fp)

    extra = 1
    while extra == 1:
        _, _, _, extra = tagBits(fp, \
            ('quantiser_scale_code', 5),
            ('intra_slice_flag', 1),
            ('intra_slice', 1),
            ('extra', 1)
        )

        if extra == 1:
            tagUint8(fp, 'extra')

    # TODO: finish this

    tagFromPosition(fp, start, '', 'slice header')

def tag_pack_header(fp):
    mark = fp.tell()

    tag_stream_header(fp)

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

    tag(fp, 6, '', f'scr={scr:X}h scr_ext={scr_ext:X}h')

    # consume bytes [10, 11, 12, 13]
    bs = BitStream(peek(fp, 4))
    program_mux_rate = bs.stream(22)
    assert bs.stream(2) == 3
    reserved = bs.stream(5)
    pack_stuffing_length = bs.stream(3)

    tag(fp, 4, '', 'program_mux_rate=%Xh pack_stuffing_length=%Xh' % \
        (program_mux_rate, pack_stuffing_length))

    if pack_stuffing_length:
        tag(fp, pack_stuffing_length, 'stuffing')

    tagFromPosition(fp, mark, 'pack_header')

def tag_video_stream_descriptor(fp):
    # iso13818-1.pdf 2.6

    mark = fp.tell()

    tagUint8(fp, 'tag')
    descriptor_length = tagUint8(fp, 'length')

    _, _, MPEG_1_only_flag, _, _ = tagBits(fp, \
        ('multiple_frame_rate_flag', 1),
        ('frame_rate_code', 4),
        ('MPEG_1_only_flag', 1),
        ('constrained_parameter_flag', 1),
        ('still_picture_flag', 1)
    )

    if MPEG_1_only_flag == 0:
        tagUint8(fp, 'profile_level_indication')

    tagBits(fp, \
        ('chroma_format', 2),
        ('frame_rate_extension_flag', 1),
        ('reserved', 5)
    )

    tagFromPosition(fp, mark, 'video_stream_descriptor')

def tag_program_element_descriptor(fp):
    # iso13818-1.pdf 2.6

    mark = fp.tell()

    tagUint8(fp, 'tag', lambda x: program_elem_descr_tag_to_string(x))
    descriptor_length = tagUint8(fp, 'length')

    tag(fp, descriptor_length, 'data')

    tagFromPosition(fp, mark, 'program_element_descriptor')

def tag_elementary_stream_map_entry(fp):
    start = fp.tell()
    tagUint8(fp, 'type', lambda x: '('+stream_type_to_string(x)+')')
    tagUint8(fp, 'id', lambda x: '('+stream_id_to_string(x)+')')
    length = tagUint16(fp, 'length')

    i = 0
    remaining = length
    while remaining:
        mark = fp.tell()
        descr_tag = tagUint8(fp, 'tag', lambda x: '('+descriptor_tag_to_string(x)+')')
        descr_len = tagUint8(fp, 'length')
        tag(fp, descr_len, 'data')
        tagFromPosition(fp, mark, f'descriptor[{i}]')
        i += 1
        remaining -= (2 + descr_len)

    tagFromPosition(fp, start, 'elem_stream_map_entry')

def tag_program_stream_map(fp):
    # iso13818-1.pdf 2.5.4.1
    start = fp.tell()

    tag_stream_header(fp)

    tagUint16(fp, 'program_stream_map_length')

    tagBits(fp, \
        ('current_next_indicator', 1),
        ('reserved', 2),
        ('version', 5)
    )

    tagBits(fp, \
        ('reserved', 7),
        ('marker', 1)
    )

    program_stream_info_length = tagUint16(fp, 'program_stream_info_length')

    # consume program descriptors
    mark = fp.tell()
    while fp.tell() - mark < program_stream_info_length:
        tag_program_element_descriptor(fp)
    tagFromPosition(fp, mark, 'program_streams')

    elementary_stream_map_length = tagUint16(fp, 'elementary_stream_map_length')

    # consume elementary streams
    mark = fp.tell()
    while fp.tell() - mark < elementary_stream_map_length:
        tag_elementary_stream_map_entry(fp)
    tagFromPosition(fp, mark, 'elementary_streams')

    tagUint32(fp, 'crc')

    tagFromPosition(fp, start, 'program_stream_map')

def tag_pts(fp, alone=True):
    pts = 0
    bs = BitStream(peek(fp, 5))
    assert bs.stream(4) == (0b0010 if alone else 0b0011)
    pts = (pts << 3) | bs.stream(3)
    assert bs.stream(1) == 1
    pts = (pts << 15) | bs.stream(15)
    assert bs.stream(1) == 1
    pts = (pts << 15) | bs.stream(15)
    assert bs.stream(1) == 1
    tag(fp, 5, f'pts={pts:X}h')
    return pts

def tag_dts(fp):
    dts = 0
    bs = BitStream(peek(fp, 5))
    assert bs.stream(4) == 0b0001
    dts = (dts << 3) | bs.stream(3)
    assert bs.stream(1) == 1
    dts = (dts << 15) | bs.stream(15)
    assert bs.stream(1) == 1
    dts = (dts << 15) | bs.stream(15)
    assert bs.stream(1) == 1
    tag(fp, 5, f'dts={dts:X}h')
    return dts

def tag_pes_header(fp):
    start = fp.tell()

    tagBits(fp, \
        ('', 2),
        ('pes_scramble', 2),
        ('pes_pri', 1),
        ('align', 1),
        ('copyright', 1),
        ('orig_or_copy', 1)
    )

    pts, dts, escr, es_rate, _, add_copy_info, pes_crc, pes_ext = tagBits(fp, \
        ('pts', 1),
        ('dts', 1),
        ('escr', 1),
        ('es_rate', 1),
        ('dsm_trick', 1),
        ('add_copy_info', 1),
        ('pes_crc', 1),
        ('pes_ext', 1)
    )

    pes_hdr_data_len = tagUint8(fp, 'pes_hdr_data_len')

    remaining = pes_hdr_data_len

    if pts==0 and dts==0:
        pass
    elif pts==0 and dts==1:
        # forbidden
        pass
    elif pts==1 and dts==0:
        tag_pts(fp, alone=True)
        remaining -= 5
    elif pts==1 and dts==1:
        tag_pts(fp, alone=False)
        tag_dts(fp)
        remaining -= 10

    if escr:
        tag(fp, 6, '', 'escr data')
        remaining -= 6

    if es_rate:
        tag(fp, 3, '', 'es rate data')
        remaining -= 3

    if add_copy_info:
        tag(fp, 1, '', 'additional copy info')
        remaining -= 1

    if pes_crc:
        tag(fp, 2, '', 'pes crc info')
        remaining -= 2

    if pes_ext:
        tag(fp, 1, '', 'pes extension info')
        remaining -= 1

    # TODO: pes private data flag, pack header field flag, seq counter, etc.

    if remaining:
        tag(fp, remaining, 'stuffing')

    tagFromPosition(fp, start, 'pes_header')

# table E.1
def tag_pes(fp):
    start = fp.tell()

    stream_id = tag_stream_header(fp)
    length = tagUint16(fp, 'length')

    mark = fp.tell()
    tag_pes_header(fp)
    pes_hdr_len = fp.tell() - mark

    if 0:
        if stream_id == 0xE0:
            payload = peek(fp, length-pes_hdr_len)
            if payload.startswith(b'\x00\x00\x00\x01'):
                with open('/tmp/dumped.h265', 'ab') as fp2:
                    fp2.write(payload)

    tag(fp, length-pes_hdr_len, 'payload')

    tagFromPosition(fp, start, '', 'packetized elementary stream (PES)')

def tag_sequence_header(fp):
    start = fp.tell()

    tag_stream_header(fp)

    tagBits(fp, \
        ('horiz_sz', 12),
        ('vert_sz', 12)
    )

    tagBits(fp, \
        ('aspect_ratio', 4),
        ('frame_rate', 4),
    )

    _, _, _, _, m0, m1 = tagBits(fp, \
        ('bit_rate', 18),
        ('1', 1),
        ('vbv_buf_sz', 10),
        ('constr_params_flag', 1),
        ('load_intra_quant_matrix', 1),
        ('load_non_intra_quant_matrix', 1)
    )

    if m0 or m1:
        tag(fp, 8, 'table')

    tagFromPosition(fp, start, 'sequence_header')

def tag_extension_header(fp):
    start = fp.tell()

    tag_stream_header(fp)
    ext_type = peek(fp, 1)[0] >> 4
    if ext_type == 1:
        tag(fp, 6, '', 'sequence data')
    elif ext_type == 2:
        tag(fp, 12, '', 'sequence display data')
    elif ext_type == 8:
        tag(fp, 5, '', 'picture coding data')

    tagFromPosition(fp, start, 'extension')

def tag_gop(fp):
    start = fp.tell()

    tag_stream_header(fp)
    tag(fp, 4, 'data')

    tagFromPosition(fp, start, '', 'group of pictures')

def tag_stream_header(fp):
    tag(fp, 4, 'stream_header', '', peek=True)
    tag(fp, 3, 'prefix')
    return tagUint8(fp, 'id', lambda x: '('+stream_id_to_string(x)+')')

def is_at_header(fp):
    sample = int.from_bytes(peek(fp, 4), 'big')
    prefix = sample >> 8
    stream_id = sample & 0xff
    return prefix == 1 and stream_id_to_string(stream_id) != 'unknown'

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    setBigEndian()

    while (not IsEof(fp)):
        if not is_at_header(fp):
            break

        stream_id = peek(fp, 4)[3]

        if stream_id == 0:
            tag_picture_header(fp)
        elif 1 <= stream_id <= 0xaf:
            tag_slice_header(fp)
        elif stream_id == 0xba:
            tag_pack_header(fp)
        elif stream_id == 0xe0:
            tag_pes(fp)
        elif stream_id == 0xb3:
            tag_sequence_header(fp)
        elif stream_id == 0xb5:
            tag_extension_header(fp)
        elif stream_id == 0xb8:
            tag_gop(fp)
        elif stream_id == 0xbc:
            tag_program_stream_map(fp)
        elif stream_id == 0xbd:
            tag_pes(fp)
        else:
            tag_stream_header(fp)

        if not is_at_header(fp):
            break

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
