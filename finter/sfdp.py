#!/usr/bin/env python

# serial flash discoverable parameters (SFDP)
# https://www.jedec.org/standards-documents/docs/jesd216b

import os
import sys
import struct
import binascii

from . import pe
from .helpers import *

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    if peek(fp, 4) != b'SFDP':
        return

    # first is sfdp header
    tag(fp, 8, 'sfdp_header', '', peek=True)
    tagUint32(fp, 'signature')
    tagUint8(fp, 'minor_rev')
    tagUint8(fp, 'major_rev')
    nph = tagUint8(fp, 'nph', 'number param headers - 1')
    tagUint8(fp, 'unused', 'expect 0xFF')

    # which can contain some parameter table pointers
    for i in range(nph + 1):
        tag(fp, 8, 'param_header', f'{i+1}/{nph}')
        tagUint8(fp, 'jedec_id')
        tagUint8(fp, 'minor_rev')
        tagUint8(fp, 'major_rev')
        tagUint24(fp, 'ptp', 'parameter table pointer')
        tagUint8(fp, 'unused', 'expect 0xFF')

    # then parameter table definition


if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
