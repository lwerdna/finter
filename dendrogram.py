#!/usr/bin/env python

# simple dendrogram experiment
# 
# Every leaf node is a sample (row in the matrix).
# Each leaf has a single dimension: the center of its interval (column in the matrix).
#
# What will the clustering algorithm produce?

import sys
from helpers import dissect_file, intervals_to_tree

import plotly.figure_factory as ff
import numpy as np

def leaves(node):
    if not node.children:
        return [node]

    return sum([leaves(c) for c in node.children], [])

if __name__ == '__main__':

    intervals = dissect_file(sys.argv[1])
    tree = intervals_to_tree(intervals)
    leaves = leaves(tree)

    print('%d leaves' % len(leaves))
    X = np.zeros((len(leaves),1))

    # <len(leaves)> rows, 1 columns
    names = []
    for i in range(len(leaves)):
        names.append(leaves[i].comment)
        for col in range(1):
            X[i][col] = leaves[i].begin + len(leaves[i])/2.0

    print(X)
    fig = ff.create_dendrogram(X, orientation='left', labels=names)
    fig.update_layout(width=8000, height=5000)
    fig.write_html('/tmp/tmp.html')

