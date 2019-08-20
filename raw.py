#!/usr/bin/env python

import sys
import helpers

if __name__ == '__main__':
    for (i,line) in enumerate(helpers.dissect_file(sys.argv[1])):
        print('%d: %s' % (i, line))

