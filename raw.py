#!/usr/bin/env python

import sys
import helpers

if __name__ == '__main__':
    fpath = sys.argv[1]
    analyze = helpers.find_dissector(fpath)
    if not analyze:
        raise Exception('no dissector found')

    with open(fpath, 'rb') as fp:
        analyze(fp)

