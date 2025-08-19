#!/usr/bin/env python

# References:
# 1. A Warm Welcome to ASN.1 and DER
#    https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

import io
import sys

from .helpers import *

def read_length(fp):
    # normal length
    length = uint8(fp)

    # extended length?
    if length >> 7:
        lbytes = length & 0x7F

        # indefinite length?
        if lbytes == 0:
            raise Exception('indefinite lengths not supported')

        length = int.from_bytes(fp.read(lbytes), 'big')

    return length

def tag_length(fp):
    start = fp.tell()
    length = read_length(fp)
    tagFromPosition(fp, start, f'length=0x{length:x}')
    return length

def tag_integer(fp):
    start = fp.tell()

    # skip tag
    fp.read(1)
    # get length
    length = read_length(fp)
    # get bytes
    data = fp.read(length)
    # check msb for neg flag
    factor = 1
    if data[0] & 0x80:
        factor = -1
        data[0] = data[0] & 0x7F

    value = int.from_bytes(data, 'big') * factor

    tagFromPosition(fp, start, str(value))

def tag_tlv(fp):
    start = fp.tell()

    tag_ = uint8(fp, peek=True)
    #  bits: AABCCCCC
    #
    #    AA: class
    #     B: constructed/primitive
    # CCCCC: type
    type_ = tag_ & 0x1F #
    nonprim = (tag_ >> 5) & 1
    class_ = tag_ >> 6

    # TODO: use enums
    #if class_ == 0 and type_ == 2:
    #    tag_integer(fp)
    #    return

    # TODO: use enums
    if class_ == 0:
        type_name = {   2: 'INTEGER',
                        3: 'BIG_STRING',
                        4: 'OCTET_STRING',
                        5: 'NULL',
                        6: 'OBJECT_ID',
                        12: 'UTF8String',
                        16: 'SEQUENCE[OF]',
                        17: 'SET[OF]',
                        19: 'PrintableString',
                        22: 'IA5String',
                        23: 'UTCTime',
                        24: 'GeneralizedTime'
                    }.get(type_, '(UNKNOWN)')
    else:
        type_name = '?'

    class_ = ['Universal', 'Application', 'Context-specific', 'Private'][type_ >> 6]

    tagUint8(fp, 'tag', f'({class_}.{type_name})')

    mark = fp.tell()
    indefinite = False
    length = tag_length(fp)
    #tagFromPosition(fp, mark, f'length: {length:X}h')

    if nonprim:
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
