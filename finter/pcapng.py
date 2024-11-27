#!/usr/bin/env python

# 
# https://github.com/pcapng/pcapng/
# https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap
# https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

VERIFY_2ND_TOTALBLOCKLENGTH = True

import io
import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *
from . import networking

from enum import Enum, auto, unique

frame_index = None
link_type = None

class BLOCK_TYPE(Enum):
    SECTION_HEADER = 0x0a0d0d0a
    INTERFACE_DESCRIPTION = 1
    ENHANCED_PACKET = 6

class LINKTYPE(Enum):
    NULL = 0
    ETHERNET = 1
    EXP_ETHERNET = 2
    AX25 = 3
    PRONET = 4

###############################################################################
# "main"
###############################################################################

def tag_block_header(fp):
    global VERIFY_2ND_TOTALBLOCKLENGTH

    start = fp.tell()
    type_ = tagUint32(fp, 'BlockType', lambda x: enum_int_to_name(BLOCK_TYPE, x))
    BlockTotalLength = tagUint32(fp, 'BlockTotalLength')

    # check the second TotalLength field
    if VERIFY_2ND_TOTALBLOCKLENGTH:
        here = fp.tell()
        fp.seek(BlockTotalLength-12, io.SEEK_CUR)
        assert uint32(fp) == BlockTotalLength
        fp.seek(here)

    tagFromPosition(fp, start, 'BlockHeader')

    return BlockTotalLength

def tag_section_header_block(fp, BlockTotalLength):
    start = fp.tell()
    tag_block_header(fp)

    bom = tagUint32(fp, 'ByteOrderMagic')
    assert bom == 0x1a2b3c4d
    major_version = tagUint16(fp, 'MajorVersion')
    minor_version = tagUint16(fp, 'MinorVersion')
    section_length = tagUint64(fp, 'SectionLength')

    optionsLength = BlockTotalLength - (fp.tell() - start) - 4 # -4 for 2nd BlockTotalLength
    tag(fp, optionsLength, 'Options')

    tagUint32(fp, 'BlockTotalLength (repeated)')

    tagFromPosition(fp, start, 'SectionHeaderBlock')

def tag_interface_description_block(fp, BlockTotalLength):
    global link_type

    start = fp.tell()
    tag_block_header(fp)

    link_type = tagUint16(fp, 'LinkType', lambda x: enum_int_to_name(LINKTYPE, x))
    tagUint16(fp, 'Reserved')
    tagUint32(fp, 'SnapLen')
    tag(fp, BlockTotalLength -4 -4 -2 -2 -4 -4, 'Options')

    tagUint32(fp, 'TotalLength (repeated)')

    tagFromPosition(fp, start, 'InterfaceDescriptionBlock')

def tag_enhanced_packet_block(fp, BlockTotalLength):
    print('// tag_enhanced_packet_block()')

    global frame_index
    global link_type

    start = fp.tell()
    tag_block_header(fp)

    tagUint32(fp, 'Interface ID')
    tagUint32(fp, 'Timestamp (upper)')
    tagUint32(fp, 'Timestamp (lower)')
    capturedPacketLength = tagUint32(fp, 'CapturedPacketLength')
    tagUint32(fp, 'OriginalPacketLength')

    packetDataLength = 4 * ((capturedPacketLength+3) // 4)

    mark = fp.tell()
    if link_type is not None and LINKTYPE(link_type) == LINKTYPE.ETHERNET:
        networking.ethernet(fp, packetDataLength, descend=True)
    else:
        tag(fp, packetDataLength, f'packetData ({packetDataLength}/0x{packetDataLength:x} bytes)')

    mark2 = mark + packetDataLength
    if fp.tell() > mark2:
        raise Exception(f'ERROR: descent consumed {fp.tell()-mark} bytes when only {packetDataLength} were available')
    elif fp.tell() < mark2:
        raise Exception(f'ERROR: descent consumed {fp.tell()-mark} bytes they should have consumed {packetDataLength}')

    optionsLength = BlockTotalLength - (fp.tell() - start) - 4 # -4 for the 2nd BlockTotalLength
    assert optionsLength >= 0
    if optionsLength:
        tag(fp, optionsLength, 'Options')

    tagUint32(fp, 'TotalLength (repeated)')

    tagFromPosition(fp, start, 'Block', f'EnhancedPacketBlock (index: {frame_index})')

def tag_block(fp):
    global frame_index

    start = fp.tell()

    extra = ''

    BlockType, BlockTotalLength = struct.unpack('<II', peek(fp, 8))

    # BlockType   (4)
    # BodyLength  (4)
    # Body        (<BodyLength>)
    # BodyLength  (4)            (yes, this value is actually repeated)

    # section header block
    if BlockType == 0x0a0d0d0a:
        tag_section_header_block(fp, BlockTotalLength)
    # interface description block
    elif BlockType == 1:
        tag_interface_description_block(fp, BlockTotalLength)
    # enahnced packet block
    elif BlockType == 6:
        tag_enhanced_packet_block(fp, BlockTotalLength)
        frame_index += 1
        extra = f' (index: {frame_index})'
    else:
        body = tag(fp, BlockTotalLength, f'Block (type:{BlockType}) body{extra}')
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
