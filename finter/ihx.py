#!/usr/bin/env python

import re
import sys
import binascii
from struct import unpack

from .helpers import *

def analyze(fp):
    fp.seek(0)

    while not IsEof(fp):
        line = dataUntil(fp, b'\x0a', 1).decode('utf-8')
       
        m = re.match(r'^:(..)(....)00(.*)(..)', line)
        if m:
            (count, addr, data, csum) = m.group(1,2,3,4)
            assert int(count,16) == len(data)/2
            tagDataUntil(fp, b'\x0a', 'DATA %s: %s' % (addr, data))
            continue

        m = re.match(r'^:00000001FF', line)
        if m:
            tagDataUntil(fp, b'\x0a', 'EOF')
            continue

        m = re.match(r'^:02(....)02(....)(..)', line)
        if m:
            (addr, saddr, csum) = m.group(1,2,3)
            tagDataUntil(fp, b'\x0a', 'EXTENDED SEGMENT ADDR %s' % (saddr))
            continue

        m = re.match(r'^:04(....)03(....)(....)(..)', line)
        if m:
            (addr, cs, ip, csum) = m.group(1,2,3,4)
            tagDataUntil(fp, b'\x0a', 'START SEGMENT ADDR %s:%s' % (cs, ip))
            continue

        m = re.match(r'^:02(....)04(....)(..)', line)
        if m:
            (addr, upper16, csum) = m.group(1,2,3,4)
            tagDataUntil(fp, b'\x0a', 'EXTENDED LINEAR ADDR %s0000' % (csum))
            continue

        m = re.match(r'^:04(....)05(........)(..)', line)
        if m:
            (addr, linear, csum) = m.group(1,2,3,4)
            tagDataUntil(fp, b'\x0a', 'START LINEAR ADDR %s' % (linear))
            continue

        tagDataUntil(fp, b'\x0a', 'UNKNOWN')

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
