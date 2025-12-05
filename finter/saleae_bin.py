#!/usr/bin/env python

# https://support.saleae.com/getting-help/troubleshooting/technical-faq/binary-export-format-logic-2

import os
import sys
import struct

from .helpers import *

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    base = fp.tell()
    identifier = fp.read(8)
    version = uint32(fp)
    fp.seek(base)

    if identifier != b'<SALEAE>' or version != 0:
        return

    tagString(fp, 8, 'identifier')

    tagUint32(fp, 'version')
    tagUint32(fp, 'type')
    initial_state = tagUint32(fp, 'initial_state')
    tagDouble(fp, 'begin_time')
    tagDouble(fp, 'end_time')
    num_transitions = tagUint64(fp, 'num_transitions')

    current_state = initial_state
    for i in range(num_transitions):
        tagDouble(fp, f'transition{i}')

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
