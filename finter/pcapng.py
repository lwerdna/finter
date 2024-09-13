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

def tag_block_header(fp):
    start = fp.tell()
    type_ = tagUint32(fp, 'Type', lambda x: block_id_tostr(x))
    length = tagUint32(fp, 'TotalLength')

    # check the second TotalLength field
    here = fp.tell()
    fp.seek(length)
    #assert uint32(fp, True) == length
    fp.seek(here)

    #tagUint32(fp, 'TotalLength (repeated)')

    tagFromPosition(fp, start, 'BlockHeader')

    return length

def tag_section_header_block(fp, length):
    start = fp.tell()
    tag_block_header(fp)

    bom = tagUint32(fp, 'ByteOrderMagic')
    assert bom == 0x1a2b3c4d
    major_version = tagUint16(fp, 'MajorVersion')
    minor_version = tagUint16(fp, 'MinorVersion')
    section_length = tagUint64(fp, 'SectionLength')

    # minus 12 for the block header type, length, length
    # minus 16 for the bom, major_version, minor_version
    tag(fp, length-12-16, 'Options')

    tagUint32(fp, 'TotalLength (repeated)')

    tagFromPosition(fp, start, 'SectionHeaderBlock')

def tag_interface_description_block(fp, length):
    start = fp.tell()
    tag_block_header(fp)

    tagUint16(fp, 'LinkType', lambda x: linktype_tostr(x))
    tagUint16(fp, 'Reserved')
    tagUint32(fp, 'SnapLen')
    tag(fp, length - 8, 'Options')

    tagUint32(fp, 'TotalLength (repeated)')

    tagFromPosition(fp, start, 'InterfaceDescriptionBlock')

def tag_enhanced_packet_block(fp, length):
    start = fp.tell()
    tag_block_header(fp)

    tagUint32(fp, 'Interface ID')
    tagUint32(fp, 'Timestamp (upper)')
    tagUint32(fp, 'Timestamp (lower)')
    capturedPacketLength = tagUint32(fp, 'CapturedPacketLength')
    tagUint32(fp, 'OriginalPacketLength')

    packetDataLength = 4 * ((capturedPacketLength+3) // 4)
    tag(fp, packetDataLength, 'packetData')

    optionsLength = length + 8 - (fp.tell() - start)
    print(f'optionsLength: {optionsLength}')
    assert optionsLength >= 0
    if optionsLength:
        tag(fp, 'Options', optionsLength)

    tagUint32(fp, 'TotalLength (repeated)')

    tagFromPosition(fp, start, 'Block', f'EnhancedPacketBlock (index: {frame_index})')

frame_index = None

def tag_block(fp):
    global frame_index

    start = fp.tell()

    extra = ''

    type_, total_length0 = struct.unpack('<II', peek(fp, 8))

    # BlockType   (4)
    # BodyLength  (4)
    # Body        (<BodyLength)
    # BodyLength  (4)            (yes, repeated)

    body_length = total_length0 - 12
    if body_length:
        # section header block
        if type_ == 0x0a0d0d0a:
            tag_section_header_block(fp, body_length)
        # interface description block
        elif type_ == 1:
            tag_interface_description_block(fp, body_length)
        # enahnced packet block
        elif type_ == 6:
            tag_enhanced_packet_block(fp, body_length)
            frame_index += 1
            extra = f' (index: {frame_index})'
        else:
            body = tag(fp, body_length, f'body{extra}')
            #tagUint32(fp, 'TotalLength (repeated)')

def analyze(fp):
    global frame_index

    setLittleEndian()

    frame_index = 1
    while not IsEof(fp):
        tag_block(fp)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
