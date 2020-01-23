#!/usr/bin/env python
#
# display given file as offset, hex, ascii (OHA)

import re
import io
import sys
from intervaltree import Interval, IntervalTree
from helpers import dissect_file, intervals_from_text, interval_tree_to_hierarchy

RED = '\x1B[31m'
GREEN = '\x1B[32m'
ORANGE = '\x1B[33m'
PURPLE = '\x1B[35m'
YELLOW = '\x1B[93m'
CYAN = '\x1B[96m'
NORMAL = '\x1B[0m'

class ohaNode():
    def __init__(self, interval):
        self.interval = interval
        self.children = []

    def setfp(self, fp):
        self.fp = fp
        for child in self.children:
            child.setfp(fp)

    def pprint(self, depth=0):
        addr = self.interval.begin
        length = self.interval.length()
        end = addr + length
        comment = self.interval.data
        if comment:
            comment = '.'*depth + comment

        # base case: no children, just print oha
        if not self.children:
            self.fp.seek(addr)

            if length > 1024:
                addr = (addr + 1024) & 0xFFFFFFFFFFFFFFFF0
                data = self.fp.read(1024)
                oha(data, addr, comment)
                print('%s~~~~~~~~%s' % (YELLOW, NORMAL))
            else:
                data = self.fp.read(length)
                oha(data, addr, comment)

            return

        # recur on gaps, children
        children = sorted(self.children, key=lambda x: x.interval.begin)

        # write our own name, either on the initial fragment...
        if addr < children[0].interval.begin:
            tmp = ohaNode(Interval(addr, children[0].interval.begin, self.interval.data))
            tmp.setfp(self.fp)
            tmp.pprint(depth)
            addr = children[0].interval.begin
        # ... or on empty line
        else:
            oha('', self.interval.begin, comment)

        for child in children:
            cbegin = child.interval.begin
            # gap
            if addr < cbegin:
                tmp = ohaNode(Interval(addr, cbegin, 'fragment'))
                tmp.setfp(self.fp)
                tmp.pprint(depth+1)
                addr = cbegin

            assert addr == cbegin
            child.pprint(depth+1)
            addr = cbegin + child.interval.length()
        # recur on gap after last child
        if addr < end:
            tmp = ohaNode(Interval(addr, end, 'fragment'))
            tmp.setfp(self.fp)
            tmp.pprint(depth+1)

def oha(data, addr, comment=None):
    """ offset, hex, ascii (OHA) of data """

    result = []
    va_lo = addr
    va_hi = addr + len(data)

    va = va_lo & 0xFFFFFFF0
    while va < va_hi:
        hex_str = ''
        ascii_str = ''
        for i in range(16):
            if va+i >= va_lo and va+i < va_hi:
                x = data[va+i - va_lo]
                hex_str += '%02X ' % x
                ascii_str += chr(x) if (x > 31 and x < 127) else '.'
            else:
                hex_str += '   '
                ascii_str += ' '

        if comment:
            print('%s%08X%s %s %s%s%s %s%s%s' % \
                (YELLOW, va, NORMAL, hex_str, PURPLE, ascii_str, NORMAL, CYAN, comment, NORMAL))
            comment = ''
        else:
            print('%s%08X%s %s %s%s%s' % (YELLOW, va, NORMAL, hex_str, PURPLE, ascii_str, NORMAL))

        va += 16

    return '\n'.join(result)

if __name__ == '__main__':

#    print('--')
#    print(oha_comment(b'\x00\x00\x00\x01', 0x180CB04, 'sh_name=0x1'))
#    print('--')
#    print(oha_comment(b'\x00\x00\x00\x03', 0x180CB8, 'sh_type=0x3'))
#    print('--')
#    print(oha_comment(b'\x00\x00\x00\x00', 0x180CBC, 'sh_flags=0'))
#    print('--')
#    print(oha_comment(b'\x00\x00\x00\x00', 0x180CC0, 'sh_addr=0'))

    if not sys.argv[1:]:
        print('ERROR: missing file parameter')
        print('usage: %s <file>' % sys.argv[0])
        sys.exit(-1)

    lines = dissect_file(sys.argv[1])
    if not lines:
        print('no file dissectors answered the call')
        sys.exit(-1)

    intervals = intervals_from_text(lines)
    tree = IntervalTree(intervals)
    root = interval_tree_to_hierarchy(tree, ohaNode)

    with open(sys.argv[1], 'rb') as fp:
        root.setfp(fp)
        root.pprint()
    
