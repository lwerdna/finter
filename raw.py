#!/usr/bin/env python

import sys
import helpers

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fp:
        for analyze in helpers.dissectors:
            fp.seek(0, 0)
            analyze(fp)

