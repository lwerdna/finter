#!/usr/bin/env python

import os
import re
import sys

from .helpers import *

###############################################################################
# "main"
###############################################################################

def tagFile(fp, nametable=None):
    start = fp.tell()

    comment = 'file_ident'
    file_ident = peek(fp, 16).decode('utf-8')
    if m := re.match(r'^/(\d+)', file_ident):
        idx = int(m.group(1))
        if nametable and idx in nametable:
            comment += ': ' + nametable[idx]
    file_ident = tag(fp, 16, comment)

    tag(fp, 12, 'mod_timestamp')
    tag(fp, 6, 'owner_id')
    tag(fp, 6, 'group_id')
    tag(fp, 8, 'file_mode')
    file_size = int(tag(fp, 10, 'file_size'))
    tag(fp, 2, 'end_chars')
    #assert b'\x60\x0a' == tag(fp, 2, 'end_chars')

    offset_file = fp.tell()
    tag(fp, file_size, 'data [0x%x, 0x%x)' % (offset_file, offset_file + file_size))

    if file_size % 2:
        fp.read(1)

    tagFromPosition(fp, start, 'file_header')

    return (file_ident, offset_file, file_size)

# https://github.com/bminor/binutils-gdb/blob/master/bfd/archive.c
# produces something like:
# {  0: 'd:\\win7rtm.obj.amd64fre\\avcore\\published\\mf\\daytona\\objfre\\amd64\\guids.obj'
#   75: 'd:\\win7rtm.obj.amd64fre\\avcore\\published\\mf\\daytona\\objfre\\amd64\\mfplay_i.obj',
#  153: 'd:\\win7rtm.obj.amd64fre\\avcore\\published\\mf\\daytona\\objfre\\amd64\\mfreadwrite_i.obj',
#  ...
# }
def find_extended_name_table_svr4(fp):
    result = None

    start = fp.tell()
    while not IsEof(fp):
        file_ident = fp.read(16)
        fp.read(12+6+6+8) # consume timestamp, owner, group, mode
        file_size = int(fp.read(10))
        fp.read(2) # end chars

        if file_ident == b'//              ':
            data = fp.read(file_size)
            tmp = [i for i,c in enumerate(data) if c==0]
            starts = [0] + [i+1 for i in tmp]
            ends = [i for i in tmp] + [len(data)]
            result = {a: data[a:b].decode('utf-8') for a,b in zip(starts, ends)}
            break

        fp.seek(file_size, os.SEEK_CUR)
        if file_size % 2:
            fp.read(1)

    fp.seek(start)
    return result

def analyze(fp):
    if not peek(fp, 8) == b'!<arch>\x0a':
        return

    tag(fp, 8, 'signature')

    name_table = find_extended_name_table_svr4(fp)

    # seek

    while not IsEof(fp):
        ident, offset, size = tagFile(fp, name_table)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
