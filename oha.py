#!/usr/bin/env python
#
# display given file as offset, hex, ascii (OHA)

import re
import sys
from helpers import dissect_file, intervals_from_text, interval_tree_to_hierarchy, FinterNode

RED = '\x1B[31m'
GREEN = '\x1B[32m'
ORANGE = '\x1B[33m'
PURPLE = '\x1B[35m'
YELLOW = '\x1B[93m'
CYAN = '\x1B[96m'
NORMAL = '\x1B[0m'

# OHANode extends FinterNode by:
# - adding .fp member variable to access bytes tagged
# - adding .pretty_print() methods to output the offset, hex, ascii
class OHANode(FinterNode):
    def __init__(self, begin, end, type_, comment):
        super().__init__(begin, end, type_, comment)
        self.fp = None

    def set_fp(self, fp):
        self.fp = fp
        for child in self.children:
            child.set_fp(fp)

    def pretty_print(self, depth=0):
        comment = '  '*depth + self.comment

        if self.children:
            oha_comment(self.begin, comment)
            for child in sorted(self.children, key=lambda c: c.begin):
                child.pretty_print(depth+1)
        else:
            self.fp.seek(self.begin)
            data = self.fp.read(self.end - self.begin)
            oha(data, self.begin, comment)

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
        print('usage: %s <file> [offset]' % sys.argv[0])
        sys.exit(-1)

    fpath = sys.argv[1]

    offset = 0
    if sys.argv[2:]:
        offset = int(sys.argv[2], 16)

    interval_tree = dissect_file(fpath, offset)

    root = interval_tree_to_hierarchy(interval_tree, OHANode)

    sorted_children = sorted(root.children, key=lambda x: x.begin)

    # debug?
    if 0:
        graph(root)
        sys.exit(-1)

    with open(sys.argv[1], 'rb') as fp:
        root.set_fp(fp)

        for child in sorted_children:
            child.pretty_print()

