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

# https://www.tcpdump.org/linktypes.html
class LINKTYPE(Enum):
    NULL = 0
    ETHERNET = 1
    EXP_ETHERNET = 2
    AX25 = 3
    PRONET = 4
    LINUX_SLL2 = 276

class ARP_HARDWARE(Enum):
    ARPHRD_NETROM = 0
    ARPHRD_ETHER = 1
    ARPHRD_EETHER = 2
    ARPHRD_AX25 = 3
    ARPHRD_PRONET = 4
    ARPHRD_CHAOS = 5
    ARPHRD_IEEE802 = 6
    ARPHRD_ARCNET = 7
    ARPHRD_APPLETLK = 8
    ARPHRD_DLCI = 15
    ARPHRD_ATM = 19
    ARPHRD_METRICOM = 23
    ARPHRD_IEEE1394 = 24
    ARPHRD_EUI64 = 27
    ARPHRD_INFINIBAND = 32
    ARPHRD_SLIP = 256
    ARPHRD_CSLIP = 257
    ARPHRD_SLIP6 = 258
    ARPHRD_CSLIP6 = 259
    ARPHRD_RSRVD = 260
    ARPHRD_ADAPT = 264
    ARPHRD_ROSE = 270
    ARPHRD_X25 = 271
    ARPHRD_HWX25 = 272
    ARPHRD_CAN = 280
    ARPHRD_MCTP = 290
    ARPHRD_PPP = 512
    ARPHRD_CISCO = 513
    ARPHRD_HDLC = 513 #ARPHRD_CISCO
    ARPHRD_LAPB = 516
    ARPHRD_DDCMP = 517
    ARPHRD_RAWHDLC = 518
    ARPHRD_RAWIP = 519
    ARPHRD_TUNNEL = 768
    ARPHRD_TUNNEL6 = 769
    ARPHRD_FRAD = 770
    ARPHRD_SKIP = 771
    ARPHRD_LOOPBACK = 772
    ARPHRD_LOCALTLK = 773
    ARPHRD_FDDI = 774
    ARPHRD_BIF = 775
    ARPHRD_SIT = 776
    ARPHRD_IPDDP = 777
    ARPHRD_IPGRE = 778
    ARPHRD_PIMREG = 779
    ARPHRD_HIPPI = 780
    ARPHRD_ASH = 781
    ARPHRD_ECONET = 782
    ARPHRD_IRDA = 783
    ARPHRD_FCPP = 784
    ARPHRD_FCAL = 785
    ARPHRD_FCPL = 786
    ARPHRD_FCFABRIC = 787
    ARPHRD_IEEE802_TR = 800
    ARPHRD_IEEE80211 = 801
    ARPHRD_IEEE80211_PRISM = 802
    ARPHRD_IEEE80211_RADIOTAP = 803
    ARPHRD_IEEE802154 = 804
    ARPHRD_IEEE802154_MONITOR = 805
    ARPHRD_PHONET = 820
    ARPHRD_PHONET_PIPE = 821
    ARPHRD_CAIF = 822
    ARPHRD_IP6GRE = 823
    ARPHRD_NETLINK = 824
    ARPHRD_6LOWPAN = 825
    ARPHRD_VSOCKMON = 826
    ARPHRD_VOID = 0xFFFF
    ARPHRD_NONE = 0xFFFE

###############################################################################
# "main"
###############################################################################

def ethernet_ii(fp, length=None):
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

# https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
def linux_sll2(fp):
    endian = setBigEndian()

    start = fp.tell()
    tagUint16(fp, 'protocol_type')
    tagUint16(fp, 'reserved (mbz)')
    tagUint32(fp, 'interface index')
    tagUint16(fp, 'hw type', lambda x: enum_int_to_name(ARP_HARDWARE, x))
    tagUint8(fp, 'packet type')
    tagUint8(fp, 'link-layer address length')
    tag(fp, 8, 'link-layer address')
    tagFromPosition(fp, start, 'linux_sll2_hdr')

    setEndian(endian)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
