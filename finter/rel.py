#!/usr/bin/env python

# small device C compiler (sdcc) .rel object format
# see sdcc/sdas/doc/format.txt 
#     sdas/doc/asmlnk.txt

import re
import sys
import binascii
from struct import unpack

from .helpers import *

def analyze(fp):
    sample = fp.read(4).decode('utf-8')
    if not re.match(r'[XDQ][HL][234]\x0a', sample):
        return

    fp.seek(0)

    while not IsEof(fp):
        line = dataUntil(fp, b'\x0a', 1).decode('utf-8')
       
        m = re.match(r'^([XDQ])([HL])([234])', line)
        if m:
            (a,b,c) = m.group(1,2,3)
            
            tagDataUntil(fp, b'\x0a', None, 'FORMAT %s:%s %s:%s %s:?' % \
              (a, 'hex' if a=='X' else '?', b, 'little-end' if b=='L' else 'big-end', c))
            continue

        m = re.match(r'^H (\d+) areas (.) global symbols', line)
        if m:
            (num_areas, num_globals) = map(lambda x: int(x,16), m.group(1,2))
            tagDataUntil(fp, b'\x0a', None, 'HEADER #areas:%d #globals:%d' % (num_areas, num_globals))
            continue

        m = re.match(r'^O (.+)', line)
        if m:
            mod_name = m.group(1)
            tagDataUntil(fp, b'\x0a', None, 'OPTIONS ".optsdcc %s"' % mod_name)
            continue

        m = re.match(r'^M (.+)', line)
        if m:
            mod_name = m.group(1)
            tagDataUntil(fp, b'\x0a', None, 'MODULE "%s"' % mod_name)
            continue

        m = re.match(r'^S (.+) Def(.*)', line)
        if m:
            (a,b) = m.group(1,2)
            tagDataUntil(fp, b'\x0a', None, 'SYMBOL DEF "%s" @ 0x%s' % (a,b))
            continue

        m = re.match(r'^S (.+) Ref(.*)', line)
        if m:
            (a,b) = m.group(1,2)
            tagDataUntil(fp, b'\x0a', None, 'SYMBOL REF "%s" @ 0x%s' % (a,b))
            continue

        m = re.match(r'^A (.*) size (.*) flags (.*) addr (.*)', line)
        if m:
            (label, size, flags, addr) = m.group(1,2,3,4)
            size = int(size,16)
            addr = int(addr,16)
            tagDataUntil(fp, b'\x0a', None, 'AREA label: "%s" [0x%X, 0x%X) flags:%s' % (label, addr, addr+size, flags))
            continue            

        m = re.match(r'^T (.. ..) (.*)', line)
        if m:
            (a,b) = m.group(1,2)
            # addr "being the offset address from the  current area base address"
            addr = int(a[3:5] + a[0:2], 16)
            tagDataUntil(fp, b'\x0a', None, 'WRITE %04X: %s' % (addr, b))
            continue 

        m = re.match(r'^T (.. ..)', line)
        if m:
            (a) = m.group(1)
            addr = int(a[3:5] + a[0:2], 16)
            tagDataUntil(fp, b'\x0a', None, 'WRITE %04X: (empty)' % (addr))
            continue 

        # ABS     absolute (automatically invokes OVR) 
        # REL     relocatable 
        # OVR     overlay 
        # CON     concatenate 
        # PAG     paged area
        #
        # examples:
        # .area  TEST  (REL,CON) section is relocatable, concatenated with other sections (DEFAULT)
        # .area  DATA  (REL,OVR) section is relocatable, overlays other sections
        # .area  SYS   (ABS,OVR) section is absolute, overlayed with other sections
        # .area  PAGE  (PAG)     section is a paged section
        m = re.match(r'^R .*', line)
        if m:
            tagDataUntil(fp, b'\x0a', None, 'RELOCATION')
            continue 

        tagDataUntil(fp, b'\x0a', None, 'UNKNOWN')

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
