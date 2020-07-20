#!/usr/bin/env python

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
	if fp.read(4) != b'RIFF': return
	length = uint32(fp);
	if fp.read(4) != b'WAVE': return

	fp.seek(0)
	tagString(fp, 4, 'RIFF chunk header')
	tagUint32(fp, 'RIFF chunk length')
	tagString(fp, 4, 'RIFF chunk type')

	tag(fp, length, 'RIFF chunk data')

	fp.seek(12)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
