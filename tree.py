#!/usr/bin/env python

import re
import io
import sys
from finter import elf32, elf64
from intervaltree import Interval, IntervalTree
from helpers import dissect_file

def print_recur(tree, a, depth=0):
    indent = depth*'  '

    length = a.end - a.begin
    lengthStr = '%d'%length if length < 16 else '0x%X'%length
    print('%08X: %s(%s) %s' % (a.begin, indent, lengthStr, a.data))

    for child in sorted(tree.envelop(a)):
        if a == child: continue
        print_recur(tree, child, depth+1)

if __name__ == '__main__':
    interval_lines = dissect_file(sys.argv[1])
    if not interval_lines:
        print('no file dissectors answered the call')
        sys.exit(-1)

    intervals = []
    for (i,line) in enumerate(interval_lines.split('\n')):
        #print('line %d: %s' % (i,line))
        if not line:
            continue

        m = re.match(r'\[(.*),(.*)\) (.*)', line)
        if not m:
            raise Exception('MALFORMED: %s' % line)

        # Interval .begin .end .data
        i = Interval(int(m.group(1),16), int(m.group(2),16), m.group(3))
        intervals.append(i)

    tree = IntervalTree(intervals)

    #print('top level intervals:')
    enveloped = set()
    for a in tree:
        for b in tree.envelop(a):
            if b != a:
                enveloped.add(b)

    standalone = []
    for a in tree:
        if not a in enveloped:
            standalone.append(a)

    for a in sorted(standalone):
        print_recur(tree, a)
