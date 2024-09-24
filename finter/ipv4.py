#!/usr/bin/env python

import sys
from enum import Enum

from .helpers import *

from . import udp

class IPV4_PROTO(Enum):
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17

def ip2str(data):
    return f'%d.%d.%d.%d' % (data[0], data[1], data[2], data[3])

###############################################################################
# "main"
###############################################################################

def analyze(fp, length=None):
    endian = setBigEndian()

    start = fp.tell()

    tmp = uint8(fp, True)
    Version = tmp >> 4
    IHL = tmp & 0xF
    tagUint8(fp, '', lambda x: f'Version=0x{Version:X} IHL=0x{IHL:X}')

    tmp = uint8(fp, True)
    DSCP = tmp >> 2
    ECN = tmp & 0x3
    tagUint8(fp, '', lambda x: f'DSCP=0x{DSCP:X} ECN=0x{ECN:X}')

    tagUint16(fp, 'TotalLength')

    tagUint16(fp, 'Identification')

    tmp = uint16(fp, True)
    Flags = tmp >> 13
    FragOffset = tmp & 0x1FFF
    tagUint16(fp, '', f'Flags=0x{Flags:X} FragOffset=0x{FragOffset:X}')

    tagUint8(fp, 'TTL')

    protocol = tagUint8(fp, 'Protocol', lambda x: enum_int_to_name(IPV4_PROTO, x))

    tagUint16(fp, 'HeaderChecksum')

    tag(fp, 4, 'SrcAddr', lambda x: ip2str(x))
    tag(fp, 4, 'DstAddr', lambda x: ip2str(x))

    offs = 20

    if IHL > 5:
        for i in range(0, IHL-5):
            tagUint32(fp, f'Options[{i}]')
            offs += 4
    
    assert offs < length

    if protocol == IPV4_PROTO.UDP.value:
        udp.analyze(fp, length - offs)
    else:
        tag(fp, length - offs, 'Payload')

    tagFromPosition(fp, start, 'IPV4')

    setEndian(endian)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
