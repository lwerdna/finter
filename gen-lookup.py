#!/usr/bin/env python

import sys
from helpers import dissect_file, intervals_to_tree

def get_descr(hnode):
    result = hnode.data if hnode.data != 'root' else ''
    #if ' ' in result:
    #    result = result.replace(' ', '_')
    #if '=' in result:
    #    result = result[0:result.find('=')]

    if hnode.parent:
        tmp = get_descr(hnode.parent)
        result = tmp + (', ' if tmp else '') + result

    return result

def print_recur(hnode, depth=0):
    if hnode.data == 'fragment':
        return ''

    indent = depth*'    '

    length = hnode.end - hnode.begin
    length_str = '%d'%length if length < 16 else '0x%X'%length

    descr = get_descr(hnode)

    print('%sif addr >= 0x%X and addr < 0x%X:' % (indent, hnode.begin, hnode.end))

    for child in sorted(hnode.children, key=lambda x: x.begin):
        print_recur(child, depth+1)

    print('%sreturn \'%s\'' % (indent+'    ', descr))

if __name__ == '__main__':
    shift_amount = None
    if sys.argv[2:]:
        shift_amount = int(sys.argv[2], 16)

    tree = dissect_file(sys.argv[1])
    root = intervals_to_tree(tree)

    if shift_amount:
        def all_nodes(n):
            return [n] + sum([all_nodes(c) for c in n.children], [])

        for node in all_nodes(root):
            node.begin += shift_amount
            node.end += shift_amount

    print_recur(root)
