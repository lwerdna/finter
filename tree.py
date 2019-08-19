#!/usr/bin/env python

import re
import io
import sys
from finter import elf32, elf64
from intervaltree import Interval, IntervalTree
from helpers import dissect_file, intervals_from_text, interval_tree_to_hierarchy

def print_recur(hnode, depth=0):
    indent = depth*'  '

    a = hnode.interval
    length = a.length()
    lengthStr = '%d'%length if length < 16 else '0x%X'%length
    print('%08X: %s(%s) %s' % (a.begin, indent, lengthStr, a.data))

    for child in sorted(hnode.children, key=lambda x: x.interval.begin):
        print_recur(child, depth+1)

if __name__ == '__main__':
    lines = dissect_file(sys.argv[1])
    if not lines:
        print('no file dissectors answered the call')
        sys.exit(-1)

    intervals = intervals_from_text(lines)
    tree = IntervalTree(intervals)
    hnRoot = interval_tree_to_hierarchy(tree)

    print_recur(hnRoot)
