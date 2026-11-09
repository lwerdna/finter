#!/usr/bin/env python

import sys

import plotly.express as px
import plotly.graph_objects as go

from helpers import dissect_file, intervals_to_tree

if __name__ == '__main__':
    tree = dissect_file(sys.argv[1])
    root = intervals_to_tree(tree)

    #
    ids = []
    labels = []
    parents = []

    # compute ids and labels for each node
    def all_nodes(n):
        return [n] + sum([all_nodes(c) for c in n.children], [])

    for n in all_nodes(root):
        ids.append(id(n))

        label = f'[0x{n.begin:X}, 0x{n.end:X})\n{n.comment}'
        labels.append(label)

    # compute edges (parent pointer) for each node
    child_to_parent = {}

    def all_edges(n):
        result = [(n, c) for c in n.children]
        result = result + sum([all_edges(c) for c in n.children], [])
        return result

    for (a, b) in all_edges(root):
        child_to_parent[id(b)] = id(a)

    parents = [child_to_parent.get(i) for i in ids]
    
    # put into graph object
    graph_object = go.Icicle(
        ids=[str(i) for i in ids],
        labels=labels,
        parents=[('' if p is None else str(p)) for p in parents]
    )

    print(graph_object)

    fig = go.Figure(graph_object)

    print(fig)

    # Configure orientation: root on left, leaves on right
    fig.update_traces(
        sort=False,
        tiling=dict(orientation="h"),
        textinfo="label",
    )

    fig.update_layout(
        width=1200,
        height=600,
        margin=dict(l=10, r=10, t=10, b=10),
    )

    # Save interactive version
    fpath_out = '/tmp/icicle.html'
    print(f'writing: {fpath_out}')
    fig.write_html(fpath_out, include_plotlyjs=True)

    # Save static vector version
    fpath_out = '/tmp/icicle.svg'
    print(f'writing: {fpath_out}')
    fig.write_image(fpath_out)

