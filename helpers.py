#!/usr/bin/env python

import io
import sys

from finter import *

dissectors = [
    elf32.analyze,
    elf64.analyze,
    gpg.analyze
]

def dissect_file(fpath):
    """ try all dissectors on given file path """

    # capture stdout to StringIO
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf

    # call all analyzers
    interval_lines = ''
    with open(fpath, 'rb') as fp:
        for analyze in dissectors:
            #sys.stderr.write('trying: %s\n' % analyze)
            fp.seek(0, 0)
            analyze(fp)
            interval_lines = buf.getvalue()
            if interval_lines:
                break

    # cleanup, return
    buf.close()
    sys.stdout = old_stdout
    return interval_lines
