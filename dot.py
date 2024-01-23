#!/usr/bin/env python

import sys
from helpers import dissect_file, interval_tree_to_hierarchy

if __name__ == '__main__':
    tree = dissect_file(sys.argv[1])
    root = interval_tree_to_hierarchy(tree)

    dot = []
    dot.append('digraph G {')

    # global graph settings
    dot.append('// global settings')
    dot.append('graph [rankdir="LR"]')
    dot.append('node [];')
    dot.append('edge [];')

    # node list
    def all_nodes(n):
        return [n] + sum([all_nodes(c) for c in n.children], [])

    dot.append('// nodes')
    for n in all_nodes(root):
        label = f'[0x{n.begin:X}, 0x{n.end:X})\\l{n.comment}'
        label = label.replace('"', '\\"')
        dot.append(f'{id(n)} [label="{label}"];')

    def all_edges(n):
        result = [(n, c) for c in n.children]
        result = result + sum([all_edges(c) for c in n.children], [])
        return result

    # edge list
    dot.append('// edges')
    for (a, b) in all_edges(root):
        dot.append(f'{id(a)} -> {id(b)}')

    dot.append('}')

    print('\n'.join(dot))
    sys.exit(0)

