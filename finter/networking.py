#!/usr/bin/env python

import sys
from enum import Enum

from .helpers import *

###############################################################################
# link layer
###############################################################################

def mac2str(data):
    return f'%02X:%02X:%02X:%02X:%02X:%02X' % (data[0], data[1], data[2], data[3], data[4], data[5])

class ETHER_TYPE(Enum):
    ETH_P_IP = 0x0800
    ETH_P_ARP = 0x0806
    ETH_P_IPV6 = 0x86DD
    ETH_P_LOOPBACK = 0x9000
    # TODO: add the others
    # https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h

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

def ethernet_ii(fp, length=None, descend=False):
    print(f'// ethernet_ii(length={length}/0x{length:x})')

    endian = setBigEndian()

    mark = fp.tell()

    tag(fp, 6, 'DstMac', lambda x: mac2str(x))
    tag(fp, 6, 'SrcMac', lambda x: mac2str(x))
    etype = tagUint16(fp, 'Type', lambda x: enum_int_to_name(ETHER_TYPE, x))

    tagFromPosition(fp, mark, 'ethernet II header')

    if length is not None and length-14 > 0:
        mark = fp.tell()

        descended = False
        if descend:
            if ETHER_TYPE(etype) == ETHER_TYPE.ETH_P_IP:
                ipv4(fp, length-14, descend=descend)
                descended = True

        if not descended:
            fp.seek(length-14, io.SEEK_CUR)

        tagFromPosition(fp, mark, 'ethernet II payload')

    setEndian(endian)

def ethernet_802_3(fp, length=None, descend=False):
    print('// ethernet_802_3()')

    endian = setBigEndian()

    mark = fp.tell()

    tag(fp, 6, 'DstMac', lambda x: mac2str(x))
    tag(fp, 6, 'SrcMac', lambda x: mac2str(x))
    length = tagUint16(fp, 'Length')

    tagFromPosition(fp, mark, 'ethernet 802.3 header')

    # > Since the recipient still needs to know how to interpret the frame, the
    # > standard required an IEEE 802.2 header to follow the length and specify
    # > the type. TODO

    # https://en.wikipedia.org/wiki/IEEE_802.2

    tag(fp, length, 'ethernet 802.3 payload')

    setEndian(endian)

def ethernet(fp, length=None, descend=False):
    print('// ethernet()')

    # there are multiple ethernet frames:
    # - Ethernet II
    # - Novell raw IEEE 802.3
    # - IEEE 802.2 Logical Link Control (LLC) TODO
    # - IEEE 802.2 Subnetwork Access Protocol (SNAP) TODO

    endian = setBigEndian()

    # read the type/length field to distinguish Ethernet II from 802.3
    mark = fp.tell()
    fp.seek(6+6, io.SEEK_CUR)
    tmp = uint16(fp)
    fp.seek(mark, io.SEEK_SET)

    # see "Ethernet Frame Differentiation" at https://en.wikipedia.org/wiki/Ethernet_frame

    # ethernet ii
    if tmp > 0x0600:
        ethernet_ii(fp, length, descend=descend)
    # 802.3
    else:
        ethernet_802_3(fp, length, descend=descend)

    setEndian(endian)

###############################################################################
# network layer
###############################################################################

class IPV4_PROTO(Enum):
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17

def ip2str(data):
    return f'%d.%d.%d.%d' % (data[0], data[1], data[2], data[3])

def ipv4(fp, length=None, descend=False):
    print(f'// ipv4(length={length}/0x{length:x}, descend={descend})')

    endian = setBigEndian()

    mark = fp.tell()

    tmp = uint8(fp, True)
    Version = tmp >> 4
    IHL = tmp & 0xF
    tagUint8(fp, '', lambda x: f'Version=0x{Version:X} IHL=0x{IHL:X}')

    tmp = uint8(fp, True)
    DSCP = tmp >> 2
    ECN = tmp & 0x3
    tagUint8(fp, '', lambda x: f'DSCP=0x{DSCP:X} ECN=0x{ECN:X}')

    TotalLength = tagUint16(fp, 'TotalLength')

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

    tagFromPosition(fp, mark, 'ipv4 header')

    mark = fp.tell()

    descended = False
    if descend:
        if protocol == IPV4_PROTO.UDP.value:
            udp(fp, TotalLength - offs, descend=descend)
            descended = True
        elif protocol == IPV4_PROTO.TCP.value:
            tcp(fp, TotalLength - offs, descend=descend)
            descended = True

    if not descended:
        fp.seek(TotalLength - offs, io.SEEK_CUR)

    tagFromPosition(fp, mark, 'ipv4 payload')

    if length > TotalLength:
        tag(fp, length-TotalLength, 'ipv4 payload (gap)')

    setEndian(endian)

# length: of data to follow, including udp header
def udp(fp, length=None, descend=False):
    print(f'// udp(length={length}/0x{length:x})')

    endian = setBigEndian()

    if length < 8:
        if length > 0:
            tag(fp, length, 'truncated udp header')
        return

    mark = fp.tell()
    tagUint16(fp, 'SrcPort', lambda x: f'({x:d})')
    tagUint16(fp, 'DstPort', lambda x: f'({x:d})')
    length_udp = tagUint16(fp, 'Length', lambda x: f'({x:d})') # includes UDP header
    tagUint16(fp, 'Checksum')
    tagFromPosition(fp, mark, 'udp header')

    # double check payload size from container (probably IP) and UDP
    length_udp_payload_declared = length_udp - 8
    length_udp_payload_calculated = length - 8
    delta = length_udp_payload_calculated - length_udp_payload_declared

    # if the check failed, just declared payload and be done
    if delta > 0:
        tag(fp, length_udp_payload_declared, f'udp payload')
        tag(fp, delta, 'udp payload (gap)')
    elif delta < 0:
        tag(fp, length_udp_payload_calculated, f'udp payload (truncated)')
    # if check succeeds, risk descent
    else:
        mark = fp.tell()
        descended = False
        if descend:
            sample = peek(fp, 5)
            # guess TZSP ver=1 type=0 (rx'd pkt) proto=Ether no tags
            if sample == b'\x01\x00\x00\x01\x01':
                tzsp(fp, length-8, descend=descend)
                descended = True

        if not descended:
            fp.seek(length_udp_payload_declared, io.SEEK_CUR)

        tagFromPosition(fp, mark, 'udp payload')

    setEndian(endian)

def tcp(fp, length, descend=False):
    start = fp.tell()

    tagUint16(fp, 'SrcPort')
    tagUint16(fp, 'DstPort')
    tagUint32(fp, 'SeqNum')
    tagUint32(fp, 'AckNum')

    tmp = uint16(fp, peek=True)
    flags = []
    if tmp & (1<<7):
        flags.append('CWR')
    if tmp & (1<<6):
        flags.append('ECE')
    if tmp & (1<<5):
        flags.append('URG')
    if tmp & (1<<4):
        flags.append('ACK')
    if tmp & (1<<3):
        flags.append('PSH')
    if tmp & (1<<2):
        flags.append('RST')
    if tmp & (1<<1):
        flags.append('SYN')
    if tmp & (1<<0):
        flags.append('FIN')

    data_offs = tmp >> 12
    tagUint16(fp, 'octet12', f'data_offs={data_offs} {"|".join(flags)}')

    tagUint16(fp, 'Window')
    tagUint16(fp, 'Checksum')
    tagUint16(fp, 'UrgentPtr')

    options_i = 0
    while fp.tell() < start + 4*data_offs:
        tagUint32(fp, f'options{options_i}')
        options_i += 1

    tagFromPosition(fp, start, 'tcp header')

    tag(fp, length - 4*data_offs, 'tcp payload')

# https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
def linux_sll2(fp, length, descend=False):
    print('// linux_sll2()')

    endian = setBigEndian()

    start = fp.tell()
    protocol_type = tagUint16(fp, 'protocol_type')
    tagUint16(fp, 'reserved (mbz)')
    tagUint32(fp, 'interface index')
    hw_type = tagUint16(fp, 'hw type', lambda x: enum_int_to_name(ARP_HARDWARE, x))
    tagUint8(fp, 'packet type')
    tagUint8(fp, 'link-layer address length')
    tag(fp, 8, 'link-layer address')
    tagFromPosition(fp, start, 'linux sll2 header')

    descended = False

    # decoding the protocol field depends on hardware type
    if hw_type == ARP_HARDWARE.ARPHRD_IPGRE.value:
        # protocol field contains GRE protocol type
        pass
    elif hw_type == ARP_HARDWARE.ARPHRD_IEEE80211_RADIOTAP.value:
        #
        pass
    elif hw_type == ARP_HARDWARE.ARPHRD_FRAD.value:
        #
        pass
    else:
        if protocol_type == ETHER_TYPE.ETH_P_IP.value:
            ipv4(fp, length-20, descend=descend)
            descended = True
        elif protocol_type == 0x0001:
            # TODO: Novel 802.3
            pass

    if not descended:
        tag(fp, length-20, 'linux sll2 payload')

    setEndian(endian)

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
    print(f'// tzsp(length={length}/0x{length:x})')

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

    descended = False
    if descend:
        if proto == TZSP_PROTOCOL.ETHERNET.value:
            ethernet(fp, remaining, descend=descend)
            descended = True
    if not descended:
        fp.seek(remaining, io.SEEK_CUR)

    tagFromPosition(fp, mark, 'tzsp payload')

    setEndian(endian)
