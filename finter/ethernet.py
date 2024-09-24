#!/usr/bin/env python

import sys
from enum import Enum

from .helpers import *

from . import ipv4

def mac2str(data):
    return f'%02X:%02X:%02X:%02X:%02X:%02X' % (data[0], data[1], data[2], data[3], data[4], data[5])

class ETHER_TYPE(Enum):
    IPV4 = 0x0800
    ARP = 0x0806
    IPV6 = 0x86DD

###############################################################################
# "main"
###############################################################################

def analyze(fp, length=None):
    endian = setBigEndian()

    start = fp.tell()

    tag(fp, 6, 'DstMac', lambda x: mac2str(x))
    tag(fp, 6, 'SrcMac', lambda x: mac2str(x))
    etype = tagUint16(fp, 'Type', lambda x: enum_int_to_name(ETHER_TYPE, x))

    if length is not None:
        if ETHER_TYPE(etype) == ETHER_TYPE.IPV4:
            ipv4.analyze(fp, length-14)
        else:
            tag(fp, length-14, 'Payload')

    tagFromPosition(fp, start, 'EthernetII')

    setEndian(endian)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
