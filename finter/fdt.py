#!/usr/bin/env python

# references
# 1. https://krinkinmu.github.io/2021/01/17/devicetree.html

import os
import re
import sys
from enum import Enum, auto

from .helpers import *

class TOKEN(Enum):
    FDT_BEGIN_NODE = 1
    FDT_END_NODE = 2
    FDT_PROP = 3
    FDT_NOP = 4
    FDT_END = 9

###############################################################################
# "main"
###############################################################################

def tag_fdt_header(fp):
    start = fp.tell()

    result = tagFormat(fp, 'IIIIIIIIII',
        'magic', 'totalsize', 'off_dt_struct', 'off_dt_strings',
        'off_mem_rsvmap', 'version', 'last_comp_version', 'boot_cpuid_phys',
        'size_dt_strings', 'size_dt_struct')

    tagFromPosition(fp, start, 'fdt_header')

    return result

def tag_fdt_reserve_entry(fp):
    start = fp.tell()
    tagUint64(fp, 'address')
    tagUint64(fp, 'size')
    tagFromPosition(fp, start, 'fdt_reserve_entry')

def tag_dt_strings(fp, size):
    return tag(fp, size, 'dt_strings')

def tag_dt(fp, strtab):
    start = fp.tell()

    tok = uint32(fp, peek=True)

    if tok == TOKEN.FDT_BEGIN_NODE.value:
        tagUint32(fp, 'token')
        tagStringNull(fp, 'name')
        tagFromPosition(fp, start, 'FDT_BEGIN_NODE')
    elif tok == TOKEN.FDT_END_NODE.value:
        # two same-sized nodes; make sure enveloping node declared first
        tag(fp, 4, 'FDT_END_NODE', '', peek=True)
        tagUint32(fp, 'token')
    elif tok == TOKEN.FDT_PROP.value:
        tagUint32(fp, 'token')
        len_ = tagUint32(fp, 'len')
        nameoff = uint32(fp, peek=True)
        name = strtab[nameoff: strtab.find(b'\x00', nameoff)].decode()
        nameoff = tagUint32(fp, 'nameoff')
        tag(fp, len_, 'value')
        tagFromPosition(fp, start, 'FDT_PROP', f'"{name}"')
    elif tok == TOKEN.FDT_NOP.value:
        tag(fp, 4, 'FDT_NOP', '', peek=True)
        tagUint32(fp, 'token')
    elif tok == TOKEN.FDT_END.value:
        tag(fp, 4, 'FDT_END', '', peek=True)
        tagUint32(fp, 'token')
    else:
        assert False, f'unknown token value: {tok}'

    tagPaddingUntilAlignment(fp, 4)

def tag_dt_struct(fp, length, strtab):
    start = fp.tell()

    while fp.tell() - start < length:
    #for i in range(10):
        tag_dt(fp, strtab)
    
def analyze(fp):
    if not peek(fp, 4) == b'\xd0\x0d\xfe\xed':
        return

    setBigEndian()

    fdt = tag_fdt_header(fp)

    fp.seek(fdt['off_mem_rsvmap'])
    tag_fdt_reserve_entry(fp)

    fp.seek(fdt['off_dt_strings'])
    strtab = tag_dt_strings(fp, fdt['size_dt_strings'])

    fp.seek(fdt['off_dt_struct'])
    tag_dt_struct(fp, fdt['size_dt_struct'], strtab)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
