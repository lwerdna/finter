#!/usr/bin/env python

import os
import re
import sys

from .helpers import *

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    if not peek(fp, 1) == b'\x01':
        return

    setBigEndian()

    start = fp.tell()

    tagUint8(fp, 'version')
    tagUint8(fp, 'avc profile')
    tagUint8(fp, 'avc compatibility')
    tagUint8(fp, 'avc level')

    nalu_length_minus_1 = uint8(fp, peek=True) & 3
    tag(fp, 1, f'nalu_length={nalu_length_minus_1+1}')

    num_sps_nalus = uint8(fp, peek=True) & 0x1F
    tag(fp, 1, f'num_sps_nalus={num_sps_nalus}')

    for i in range(num_sps_nalus):
        size = tagUint16(fp, 'sps size')
        tag(fp, size, 'nalu data')

    num_pps_nalus = uint8(fp, peek=True) & 0x1F
    tagUint8(fp, f'num_pps_nalus')

    for i in range(num_pps_nalus):
        size = tagUint16(fp, 'pps size')
        tag(fp, size, 'nalu data')

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
