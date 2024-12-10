#!/usr/bin/env python

# https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

import io
import sys

from .helpers import *

def tag_tlv(fp):
    start = fp.tell()

    type_ = uint8(fp, peek=True)

    class_ = None
    match type_ & 0xC0:
        case 0:
            class_ = 'Universal'
        case 1:
            class_ = 'Application'
        case 2:
            class_ = 'Context-specific'
        case 3:
            class_ = 'Private'

    tagUint8(fp, 'type/tag', f'({class_})')

    mark = fp.tell()
    indefinite = False
    length = uint8(fp)
    if length >> 7:
        lbytes = length & 0x7F
        if lbytes == 0:
            # indefinite length
            raise Exception('indefinite lengths not supported')
        length = int.from_bytes(fp.read(lbytes))
    tagFromPosition(fp, mark, f'length: {length}/0x{length:X}')

    constructed = bool(type_ & 0x20)
    if constructed:
        limit = fp.tell() + length

        while fp.tell() < limit:
            # nested tlv
            tag_tlv(fp)
    else:
        # primitive
        tag(fp, length, 'data')

    tagFromPosition(fp, start, 'TLV')

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    # start with type SEQUENCE, EXTENDED 2-byte length
    if peek(fp, 2) != b'\x30\x82':
        return

    setLittleEndian()

    while not IsEof(fp):
        tag_tlv(fp)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
