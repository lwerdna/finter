#!/usr/bin/env python

# ATAGS list, see 

import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

IH_MAGIC = 0x27051956    # Image Magic Number
IH_NMLEN = 32            # Image Name Length

class TAGID(Enum):
    ATAG_NONE = 0
    ATAG_CORE = 0x54410001
    ATAG_MEM = 0x54410002
    ATAG_VIDEOTEXT = 0x54410003
    ATAG_RAMDISK = 0x54410004
    ATAG_INITRD2 = 0x54410005
    ATAG_SERIAL = 0x54410006
    ATAG_REVISION = 0x54410007
    ATAG_VIDEOLFB = 0x54410008
    ATAG_CMDLINE = 0x54410009

###############################################################################
# "main"
###############################################################################

def tag_atag_header(fp, rewind=False):
    base = fp.tell()
    tag(fp, 8, 'header', True)
    size = tagUint32(fp, 'size', '(in 4-byte dwords)')
    tag_id = tagUint32(fp, 'id', lambda x: enum_int_to_name(TAGID, x))
    if rewind:
        fp.seek(base)
    return size, tag_id

def tag_atag_core(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    tagUint32(fp, 'flags', '(bit 0 means read-only)')
    tagUint32(fp, 'pagesize')
    tagUint32(fp, 'rootdev', '(device number)')
    fp.seek(base)
    tag(fp, size*4, "atag_core")

def tag_atag_mem(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    tagUint32(fp, 'size', '(size of the area)')
    tagUint32(fp, 'start', '(physical start address)')
    fp.seek(base)
    tag(fp, size*4, "atag_mem")

def tag_atag_videotext(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    fp.seek(base)
    tag(fp, size*4, "atag_videotext")

def tag_atag_ramdisk(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    fp.seek(base)
    tag(fp, size*4, "atag_ramdisk")

def tag_atag_initrd2(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    fp.seek(base)
    tag(fp, size*4, "atag_initrd2")

def tag_atag_serialnr(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    fp.seek(base)
    tag(fp, size*4, "atag_serialnr")

def tag_atag_revision(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    fp.seek(base)
    tag(fp, size*4, "atag_revision")

def tag_atag_video1fb(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    fp.seek(base)
    tag(fp, size*4, "atag_video1fb")

def tag_atag_cmdline(fp):
    base = fp.tell()
    size, _ = tag_atag_header(fp)
    tagString(fp, size*4 - 8, 'cmdline')
    fp.seek(base)
    tag(fp, size*4, "atag_cmdline")

def tag_atag_none(fp):
    size, _ = tag_atag_header(fp)
    assert size == 0

def tag_atag(fp):
    tmp = fp.tell()
    size = uint32(fp)
    tag_id = uint32(fp)
    fp.seek(tmp)

    ATAG_CORE = 0x54410001
    ATAG_MEM = 0x54410002
    ATAG_VIDEOTEXT = 0x54410003
    ATAG_RAMDISK = 0x54410004
    ATAG_INITRD2 = 0x54410005
    ATAG_SERIAL = 0x54410006
    ATAG_REVISION = 0x54410007
    ATAG_VIDEOLFB = 0x54410008
    ATAG_CMDLINE = 0x54410009

    if tag_id in [x.value for x in TAGID]:
        foo = TAGID(tag_id)
        match foo:
            case TAGID.ATAG_CORE:
                tag_atag_core(fp)
            case TAGID.ATAG_MEM:
                tag_atag_mem(fp)
            case TAGID.ATAG_VIDEOTEXT:
                tag_atag_videotext(fp)
            case TAGID.ATAG_RAMDISK:
                tag_atag_ramdisk(fp)
            case TAGID.ATAG_INITRD2:
                tag_atag_initrd2(fp)
            case TAGID.ATAG_SERIAL:
                tag_atag_serialnr(fp)
            case TAGID.ATAG_REVISION:
                tag_atag_revision(fp)
            case TAGID.ATAG_VIDEOLFB:
                tag_atag_videolfb(fp)
            case TAGID.ATAG_CMDLINE:
                tag_atag_cmdline(fp)
            case TAGID.ATAG_NONE:
                tag_atag_none(fp)

        return foo == TAGID.ATAG_NONE
    else:
        tag(fp, size*4, f'atag_unknown_{tag_id:08X}', True)
        tag_atag_header(fp)
        tag(fp, size*4 - 8, 'body')

def analyze(fp):
    setLittleEndian()

    # test that first entry should be CORE
    tmp = fp.tell()
    size = uint32(fp)
    tag_id = uint32(fp)
    fp.seek(tmp)

    if TAGID(tag_id) != TAGID.ATAG_CORE:
        return

    done = False
    while not done:
        done = tag_atag(fp)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
