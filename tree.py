#!/usr/bin/env python

import sys
from helpers import dissect_file, intervals_to_tree, handle_argv_common_utility

def print_recur(hnode, depth=0):
    indent = depth*'  '

    length = hnode.end - hnode.begin
    lengthStr = '%d'%length if length < 16 else '0x%X'%length
    print('[%08X, %08X) %s(len=%s type=%s) %s' % (hnode.begin, hnode.end, indent, lengthStr, hnode.type_, hnode.comment))

    for child in sorted(hnode.children, key=lambda x: x.begin):
        print_recur(child, depth+1)

if __name__ == '__main__':
    dissector, fpath, offset = handle_argv_common_utility()
    if not fpath:
        sys.exit(0)
    intervals = dissect_file(fpath, offset, dissector)
    root = intervals_to_tree(intervals)
    print_recur(root)
