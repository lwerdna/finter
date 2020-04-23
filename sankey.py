#!/usr/bin/env python

import os
import sys
from intervaltree import Interval, IntervalTree
from helpers import dissect_file, intervals_from_text, interval_tree_to_hierarchy

index2descr = {}

class sankeyNode():
    def __init__(self, interval):
        self.interval = interval
        self.children = []

    def assign_index(self, curr=0):
        self.index = curr
        print('%s took index %d' % (str(self.interval), self.index))
        index2descr[self.index] = self.interval.data

        curr += 1
        if not self.children:
            return curr

        for c in self.children:
            curr = c.assign_index(curr)
        return curr

    def sdata(self):
        source = []
        target = []
        value = []

        if self.children:
            # add our sdata
            for c in sorted(self.children, key=lambda x: x.interval.begin):
                source.append(self.index)
                target.append(c.index)
                value.append(c.interval.length())

            # collect their sdata (depth first)
            for c in sorted(self.children, key=lambda x: x.interval.begin):
                [a,b,c] = c.sdata()
                source += a
                target += b
                value += c

        # done!
        return [source, target, value]

if __name__ == '__main__':
    fpath = sys.argv[1]
    tree = dissect_file(fpath)
    root = interval_tree_to_hierarchy(tree, sankeyNode)
    root.assign_index()

    labels = [index2descr[x] for x in range(len(index2descr))]
    print('labels: ', labels)

    [source, target, value] = root.sdata()

    import plotly.graph_objects as go
    fig = go.Figure(data=[go.Sankey(
        node = dict(
          pad = 15,
          thickness = 20,
          line = dict(color = "black", width = 0.5),
          label = labels,
          color = "red"
        ),
        link = dict(
          source = source, # indices correspond to labels, eg A1, A2, A2, B1, ...
          target = target,
          value = value
      ))])

    fig.update_layout(title_text=str(os.path.basename(fpath)), font_size=10)
    fig.write_html('/tmp/tmp.html')
