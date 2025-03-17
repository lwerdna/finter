#!/usr/bin/env python

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
    tag(fp, size, 'dt_strings')

def tag_dt(fp):
    tok = tagUint32(fp, 'token', lambda x: enum_int_to_name(TOKEN, x))

def analyze(fp):
    if not peek(fp, 4) == b'\xd0\x0d\xfe\xed':
        return

    setBigEndian()

    fdt = tag_fdt_header(fp)

    fp.seek(fdt['off_mem_rsvmap'])
    tag_fdt_reserve_entry(fp)

    fp.seek(fdt['off_dt_struct'])
    tag_dt(fp)

    fp.seek(fdt['off_dt_strings'])
    tag_dt_strings(fp, fdt['size_dt_strings'])

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
