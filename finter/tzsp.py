#!/usr/bin/env python

import sys
from enum import Enum

from . import networking
from .helpers import *

###############################################################################
# TZSP https://en.wikipedia.org/wiki/TZSP
###############################################################################

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

def tzsp(fp, length=None, descend=False):
    endian = setBigEndian()

    mark = fp.tell()

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

    tagFromPosition(fp, mark, 'tzsp header')

    remaining = length - (fp.tell() - mark)

    mark = fp.tell()
    if descend:
        if proto == TZSP_PROTOCOL.ETHERNET.value:
            networking.ethernet_ii(fp, remaining, descend=descend)
    else:
        tag(fp, remaining, 'tzsp payload')

    setEndian(endian)
