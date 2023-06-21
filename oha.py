#!/usr/bin/env python3
#
# display given file as offset, hex, ascii (OHA)

import re
import sys
from helpers import dissect_file, intervals_from_text, interval_tree_to_hierarchy

RED = '\x1B[31m'
GREEN = '\x1B[32m'
ORANGE = '\x1B[33m'
PURPLE = '\x1B[35m'
YELLOW = '\x1B[93m'
CYAN = '\x1B[96m'
NORMAL = '\x1B[0m'

class OhaNode():
    def __init__(self, begin, end, comment):
        self.begin = begin
        self.end = end
        self.comment = comment
        self.children = []
        self.fp = None

    def setfp(self, fp):
        self.fp = fp
        for child in self.children:
            child.setfp(fp)

    def pprint(self, depth=0):
        comment = '  '*depth + self.comment

        first = True
        position = self.begin
        for child in sorted(self.children, key=lambda c: c.begin):
            if position == child.begin:
                if first: oha_comment(position, comment)
                child.pprint(depth+1)
                position = child.end
            else:
                fragment_length = child.begin - position
                self.fp.seek(position)
                data = self.fp.read(fragment_length)
                oha(data, position, comment if first else 'fragment')

            first = False

        # did the children cover everything?
        if position < self.end:
            fragment_length = self.end - position
            self.fp.seek(position)
            data = self.fp.read(fragment_length)
            oha(data, position, comment if first else 'fragment')

    def __str__(self):
        return f'[0x{self.begin:X} 0x{self.end:X}) {self.comment}'

def oha_comment(addr, comment):
    print(75*' '+CYAN+comment+NORMAL)

def oha(data, addr, comment=None):
    """ offset, hex, ascii (OHA) of data """

    result = []
    va_last_printed = None
    va_lo = addr
    va_hi = addr + len(data)

    va = va_lo & 0xFFFFFFF0
    while va < va_hi:
        hex_str = ''
        ascii_str = ''

        if va == va_last_printed:
            addr_str = '        '
        else:
            addr_str = '%08X' % va
            va_last_printed = va

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
            print('%s%s%s %s %s%s%s %s%s%s%s' % \
                (YELLOW, addr_str, NORMAL, hex_str, PURPLE, ascii_str, NORMAL, CYAN, cmargin, comment[0], NORMAL))
            for c in comment[1:]:
                print('%s%s%s' % (CYAN, 75*' '+cmargin + c, NORMAL))
            comment = ''
        else:
            print('%s%s%s %s %s%s%s' % (YELLOW, addr_str, NORMAL, hex_str, PURPLE, ascii_str, NORMAL))

        va += 16

    return '\n'.join(result)

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('ERROR: missing file parameter')
        print('usage: %s <file>' % sys.argv[0])
        sys.exit(-1)

    fpath = sys.argv[1]

    interval_tree = dissect_file(fpath)

    root = interval_tree_to_hierarchy(interval_tree, OhaNode)

    sorted_children = sorted(root.children, key=lambda x: x.begin)

    with open(sys.argv[1], 'rb') as fp:
        root.setfp(fp)

        for child in sorted_children:
            child.pprint()

