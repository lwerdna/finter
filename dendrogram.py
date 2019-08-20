#!/usr/bin/env python
#
# display given file as offset, hex, ascii (OHA)

import re
import io
import sys
from finter import elf32, elf64
from intervaltree import Interval, IntervalTree
from helpers import dissect_file, intervals_from_text, interval_tree_to_hierarchy

import plotly.figure_factory as ff
import numpy as np


if __name__ == '__main__':

    lines = dissect_file(sys.argv[1])
    if not lines:
        print('no file dissectors answered the call')
        sys.exit(-1)

    intervals = intervals_from_text(lines)
    print('%d intervals' % len(intervals))
    tree = IntervalTree(intervals)    

    leaves = [i for i in tree if len(tree.envelop(i))==1]
    print('%d leaves' % len(leaves))
    X = np.zeros((len(leaves),1))

    # <len(leaves)> rows, 1 columns
    names = []
    for i in range(len(leaves)):
        names.append(leaves[i].data)
        for col in range(1):
            X[i][col] = leaves[i].begin + leaves[i].length()/2.0

    print(X)
    fig = ff.create_dendrogram(X, orientation='left', labels=names)
    fig.update_layout(width=8000, height=5000)
    fig.write_html('/tmp/tmp.html')

