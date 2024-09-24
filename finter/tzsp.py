#!/usr/bin/env python

import sys
from enum import Enum

from . import ethernet
from .helpers import *

class TZSP_TYPE(Enum):
    PacketReceived = 0
    PacketForTransmit = 1
    Reserved = 2
    Configuration = 3
    KeepAlive = 4
    PortOpener = 5

class TZSP_PROTOCOL(Enum):
    ETHERNET = 1
    IEEE_802_11 = 18
    PRISM = 119
    WLAN_AVS = 127

class TZSP_TAG_TYPE(Enum):
    PADDING = 0
    END = 1
    RAW_RSSI = 10
    SNR = 11
    DATA_RATE = 12
    TIMESTAMP = 13
    CONENTION_FREE = 15
    DECRYPTED = 16
    FCS_ERROR = 17
    RX_CHANNEL = 18
    PACKET_COUNT = 40
    RX_FRAME_LENGTH = 41
    WLAN_RADIO_HDR_SERIAL = 60

###############################################################################
# "main"
###############################################################################

def analyze(fp, length=None):
    endian = setBigEndian()

    start = fp.tell()

    tagUint8(fp, 'Version')
    tagUint8(fp, 'Type', lambda x: enum_int_to_name(TZSP_TYPE, x))
    proto = tagUint16(fp, 'Protocol', lambda x: enum_int_to_name(TZSP_PROTOCOL, x))

    while True:
        tagType = tagUint8(fp, 'TagType', lambda x: enum_int_to_name(TZSP_TAG_TYPE, x))
        if tagType == TZSP_TAG_TYPE.END.value:
            break
        elif tagType == TZSP_TAG_TYPE.PADDING.value:
            continue
        else:
            taglen = tagUint8(fp, 'TagLength')
            tag(fp, taglen, 'TagData')

    remaining = length - (fp.tell() - start)
    if proto == TZSP_PROTOCOL.ETHERNET.value:
        ethernet.analyze(fp, remaining)
    else:
        tag(fp, remaining, 'Payload')

    tagFromPosition(fp, start, 'TZSP')

    setEndian(endian)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
