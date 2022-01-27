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
        tree = IntervalTree()
        tree.add(Interval(self.begin, self.end))

        for child in self.children:
            tree.chop(child.begin, child.end)
            tree.add(Interval(child.begin, child.end, child))

        intervals = sorted(tree.items())

        # if a child exists right where we start, emit a comment for this
        # enveloping structure, otherwise the first gap gets our comment
        comment = '  '*depth + self.comment

        if type(intervals[0].data) == OhaNode:
            oha_comment(self.begin, comment)
        else:
            intervals[0] = Interval(intervals[0].begin, intervals[0].end, comment)

        for interval in intervals:
            if type(interval.data) == OhaNode:
                node = interval.data
                node.pprint(depth+1)
            else:
                self.fp.seek(self.begin)
                data = self.fp.read(interval.length())
                oha(data, interval.begin, interval.data)

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

    sorted_children = sorted(root.children, key=lambda x: x.begin)

    #for top_level_node in sorted_children:
    #    print('0x%08X: %s' % (top_level_node.interval.begin, str(top_level_node.interval)))

    with open(sys.argv[1], 'rb') as fp:
        root.setfp(fp)
        for ch in sorted_children:
            ch.pprint()

