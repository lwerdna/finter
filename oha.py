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

    def __str__(self, depth=0):
        indent = '.'*depth

        if self.children:
            result = (75)*' ' + indent + CYAN + str(self.interval.data) + NORMAL + '\n'
            for c in sorted(self.children, key=lambda x: x.interval.begin):
                result += c.__str__(depth+1)
        else:
            addr = self.interval.begin
            self.fp.seek(addr)
            data = self.fp.read(self.interval.length())
            result = oha_comment(data, addr, indent + self.interval.data)

        return result + '\n'

def oha(data, addr):
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

        result.append('%s%08X%s %s %s%s%s' % (YELLOW, va, NORMAL, hex_str, PURPLE, ascii_str, NORMAL))
        va += 16

    return '\n'.join(result)

def oha_comment(data, addr, comment):
    """ OHA view with comment """
    tmp = oha(data, addr)

    comment = CYAN + comment + NORMAL

    if '\n' in tmp:
        (left,right) = tmp.split('\n', 1)
        return left + ' ' + comment + '\n' + right
    else:
        return tmp + ' ' + comment

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
        print(root)
    
