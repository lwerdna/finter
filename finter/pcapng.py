#!/usr/bin/env python

# 
# https://github.com/pcapng/pcapng/
# https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap

import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

def block_id_tostr(id_):
    match id_:
        case 0x0a0d0d0a:
            return 'Section Header Block'
        case 0x00000001:
            return 'Interface Description Block'
        case 0x00000006:
            return 'Enhanced Packet Block'
        case _:
            return '(Unknown)'

def linktype_tostr(lt):
    match lt:
        case 0:
            return 'LINKTYPE_NULL'
        case 1:
            return 'LINKTYPE_ETHERNET'
        case 2:
            return 'LINKTYPE_EXP_ETHERNET'
        case 3:
            return 'LINKTYPE_AX25'
        case 4:
            return 'LINKTYPE_PRONET'
        case _:
            return '(LINKTYPE_UNKNOWN)'

###############################################################################
# "main"
###############################################################################

def tag_section_header_block_body(fp, length):
    bom = tagUint32(fp, 'ByteOrderMagic')
    assert bom == 0x1a2b3c4d
    major_version = tagUint16(fp, 'MajorVersion')
    minor_version = tagUint16(fp, 'MinorVersion')
    section_length = tagUint64(fp, 'SectionLength')
    tag(fp, length - 16, 'Options')

def tag_interface_description_block_body(fp, length):
    tagUint16(fp, 'LinkType', lambda x: linktype_tostr(x))
    tagUint16(fp, 'Reserved')
    tagUint32(fp, 'SnapLen')
    tag(fp, length - 8, 'Options')

def tag_enhanced_packet_block_body(fp, length):
    anchor = fp.tell()

    tagUint32(fp, 'InterfaceID')
    tagUint32(fp, 'Timestamp (upper)')
    tagUint32(fp, 'Timestamp (lower)')
    capturedPacketLength = tagUint32(fp, 'CapturedPacketLength')
    tagUint32(fp, 'OriginalPacketLength')

    packetDataLength = 4 * ((capturedPacketLength+3) // 4)
    tag(fp, packetDataLength, 'packetData')

    optionsLength = length - (fp.tell() - anchor)
    assert optionsLength >= 0
    if optionsLength:
        tag(fp, 'Options', optionsLength)

def tag_block(fp):
    start = fp.tell()

    type_ = tagUint32(fp, 'type', lambda x: block_id_tostr(x))
    total_length0 = tagUint32(fp, 'total_length')
    body_length = total_length0 - 12
    if body_length:
        # section header block
        if type_ == 0x0a0d0d0a:
            tag_section_header_block_body(fp, body_length)
        # interface description block
        elif type_ == 1:
            tag_interface_description_block_body(fp, body_length)
        # enahnced packet block
        elif type_ == 6:
            tag_enhanced_packet_block_body(fp, body_length)
        else:
            body = tag(fp, body_length, 'body')
    total_length1 = tagUint32(fp, 'total_length')
    assert total_length0 == total_length1

    fp.seek(start)
    tag(fp, total_length0, 'block')

def analyze(fp):
    setLittleEndian()

    while not IsEof(fp):
        tag_block(fp)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
