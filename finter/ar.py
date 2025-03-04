#!/usr/bin/env python

import sys

from .helpers import *

###############################################################################
# "main"
###############################################################################

def tagFile(fp):
    start = fp.tell()

    tag(fp, 16, 'file_ident')
    tag(fp, 12, 'mod_timestamp')
    tag(fp, 6, 'owner_id')
    tag(fp, 6, 'group_id')
    tag(fp, 8, 'file_mode')
    file_size = int(tag(fp, 10, 'file_size'))
    tag(fp, 2, 'end_chars')
    #assert b'\x60\x0a' == tag(fp, 2, 'end_chars')

    tag(fp, file_size, 'data')
    
    if file_size % 2:
        fp.read(1)

    tagFromPosition(fp, start, 'file_header')

def analyze(fp):
    if not peek(fp, 8) == b'!<arch>\x0a':
        return

    tag(fp, 8, 'signature')

    while not IsEof(fp):
        tagFile(fp)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
