#!/usr/bin/env python

# https://wiki.wireshark.org/Development/LibpcapFileFormat

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *
from . import ethernet

from enum import Enum, auto, unique

frame_index = None
link_type = None

class BLOCK_TYPE(Enum):
    SECTION_HEADER = 0x0a0d0d0a
    INTERFACE_DESCRIPTION = 1
    ENHANCED_PACKET = 6

# TODO: populate with more from pcap/dlt.h
class LINKTYPE(Enum):
    NULL = 0
    ETHERNET = 1
    EXP_ETHERNET = 2
    AX25 = 3
    PRONET = 4

###############################################################################
# "main"
###############################################################################

def tag_global_header(fp):
    start = fp.tell()
    tagUint32(fp, 'magic', 'magic number')
    tagUint16(fp, 'version_major', 'major version number')
    tagUint16(fp, 'version_minor', 'minor version number')
    tagInt32(fp, 'thiszone', 'GMT to local correction')
    tagUint32(fp, 'sigfigs', 'accuracy of timestamps')
    tagUint32(fp, 'snaplen', 'max length of captured packets')
    tagUint32(fp, 'network', lambda x: enum_int_to_name(LINKTYPE, x))
    tagFromPosition(fp, start, 'pcap_hdr_t')

t0 = None
def tag_record_header(fp):
    global t0

    start = fp.tell()
    ts_sec = tagUint32(fp, 'ts_sec')
    ts_usec = tagUint32(fp, 'ts_usec')

    timestamp = round(ts_sec + .000001*ts_usec, 6)
    if t0 is None:
        t0 = timestamp

    delta = round(timestamp - t0, 6)

    length = tagUint32(fp, 'incl_len')
    tagUint32(fp, 'orig_len')
    tagFromPosition(fp, start, 'pcaprec_hdr_s', f't={delta}')
    return length

def analyze(fp):
    setLittleEndian()

    magic = uint32(fp, True)
    if magic == 0xa1b2c3d4:
        pass
    elif magic == 0xd4c3b2a1:
        setBigEndian()
    else:
        return

    tag_global_header(fp)

    while not IsEof(fp):
        length = tag_record_header(fp)
        tag(fp, length, 'packet data', f'({length:d} bytes)')

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
