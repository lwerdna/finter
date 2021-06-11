#!/usr/bin/env python3
#
# display given file as offset, hex, ascii (OHA)

import re
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

class OhaNode():
    def __init__(self, interval):
        self.interval = interval
        self.children = []

    def setfp(self, fp):
        self.fp = fp
        for child in self.children:
            child.setfp(fp)

    def pprint(self, depth=0):
        truncate = False
        #truncate = True
        addr = self.interval.begin
        comment = '  '*depth + self.interval.data

        if self.children:
            oha_comment(addr, comment)
            for child in sorted(self.children, key=lambda x: x.interval.begin):
                child.pprint(depth+1)
        else:
            #if length > 1024:
            length = self.interval.length()
            self.fp.seek(addr)
            data = self.fp.read(length)

            if truncate and length > 1024:
                oha(data[0:512], addr, comment)
                print('%s~~~~~~~~%s' % (YELLOW, NORMAL))
                oha(data[-512:], addr + length - 512, comment)
            else:
                oha(data, addr, comment)

def oha_comment(addr, comment):
    print(75*' '+CYAN+comment+NORMAL)

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
            (cmargin, comment) = re.match(r'^(\s*)(.*)', comment).group(1, 2)
            comment = comment.split('\\n')
            print('%s%08X%s %s %s%s%s %s%s%s%s' % \
                (YELLOW, va, NORMAL, hex_str, PURPLE, ascii_str, NORMAL, CYAN, cmargin, comment[0], NORMAL))
            for c in comment[1:]:
                print('%s%s%s' % (CYAN, 75*' '+cmargin + c, NORMAL))
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

    if len(sys.argv) < 2:
        print('ERROR: missing file parameter')
        print('usage: %s <file>' % sys.argv[0])
        sys.exit(-1)

    fpath = sys.argv[1]

    interval_tree = dissect_file(fpath)

    root = interval_tree_to_hierarchy(interval_tree, OhaNode)

    sorted_children = sorted(root.children, key=lambda x: x.interval.begin)
    #for top_level_node in sorted_children:
    #    print('0x%08X: %s' % (top_level_node.interval.begin, str(top_level_node.interval)))

    with open(sys.argv[1], 'rb') as fp:
        root.setfp(fp)
        for ch in sorted_children:
            ch.pprint()

