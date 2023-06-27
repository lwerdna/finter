import struct

from .helpers import *

GFH_HEADER_MAGIC = b'MMM'

SIG_TYPE_5_MAGIC = b'\x58\xf3\x91\xe2'

# BRLYT = "BootRom LaYouT"
BRLYT_NAME = b'BRLYT'
BRLYT_MAGIC = b'\x42\x42\x42\x42'

class GFH_TYPE_:
    FILE_INFO = 0
    BL_INFO = 1
    ANTI_CLONE = 2
    BL_SEC_KEY = 3
    BROM_CFG = 7
    BROM_SEC_CFG = 8

GFH_FILE_INFO_NAME = b'FILE_INFO'

GFH_BROM_CFG_USBDL_BY_AUTO_DETECT_TIMEOUT_EN = 0x02
GFH_BROM_CFG_USBDL_AUTO_DETECT_DIS = 0x10
GFH_BROM_CFG_USBDL_BY_KCOL0_TIMEOUT_EN = 0x80
GFH_BROM_CFG_USBDL_BY_FLAG_TIMEOUT_EN = 0x100
GFH_BROM_CFG_JUMP_BL_ARM64_EN = 0x1000
GFH_BROM_CFG_JUMP_BL_ARM64 = 0x64

BROM_SEC_CFG_JTAG_EN = 1
BROM_SEC_CFG_UART_EN = 2

#
# struct brom_layout_header {
#     char name[8];
#     __le32 version;
#     __le32 header_size;
#     __le32 total_size;
#     __le32 magic;
#     __le32 type;
#     __le32 header_size_2;
#     __le32 total_size_2;
#     __le32 unused;
# };
def brom_layout_header(fp):
    start = fp.tell()

    tag(fp, 8, 'name[8]')
    tagUint32(fp, 'version')
    header_size = tagUint32(fp, 'header_size')
    total_size = tagUint32(fp, 'total_size')
    tagUint32(fp, 'magic')
    tagUint32(fp, 'type')
    tagUint32(fp, 'header_size_2')
    tagUint32(fp, 'total_size_2')
    tagUint32(fp, 'unused')

    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct brom_layout_header')

    return {'header_size': header_size, 'total_size': total_size}

# /* Header for NOR/SD/eMMC */
# union gen_boot_header {
#     struct {
#         char name[12];
#         __le32 version;
#         __le32 size;
#     };
#     uint8_t pad[0x200];
# };
def gen_boot_header(fp):
    start = fp.tell()

    tag(fp, 12, 'name[12]')
    tagUint32(fp, 'version')
    size = tagUint32(fp, 'size (of this struct and others)')

    # obey the 0x200 padding?
    if 1:
        pad = 0x200 - (fp.tell() - start)
    # obey .size field?
    else:
        pad = size - (fp.tell() - start)
    if pad > 0:
        tag(fp, pad, f'pad[0x{pad:X}]')

    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct gen_boot_header')

    return {'size': size}

# /* Combined device header for NOR/SD/eMMC */
# struct gen_device_header {
#     union gen_boot_header boot;
#     union {
#         struct brom_layout_header brlyt;
#         uint8_t brlyt_pad[0x400];
#     };
# };
def gen_device_header(fp):
    start = fp.tell()

    # gen_boot_header.size is its size combined with neighboring headers
    info = gen_boot_header(fp)
    size = info['size']

    a = fp.tell()
    # brom_layout_header.header_size is its size combined with neighboring headers
    info = brom_layout_header(fp)
    header_size = info['header_size']

    # they should agree
    assert size == header_size

    # pad?
    space = 0x400 - (fp.tell() - start)
    if space > 0:
        tag(fp, space, f'brlyt_pad[0x{space:X}]')

    space = header_size - (fp.tell() - start)
    if space > 0:
        fp.read(space)

    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct gen_device_header')

def gfh_common_header(fp):
    start = fp.tell()

    m = tag(fp, 3, 'magic')
    assert m == GFH_HEADER_MAGIC
    tagUint8(fp, 'version')
    size = tagUint16(fp, 'size')

    def comm(val):
        lookup = {0:'GFH_TYPE_FILE_INFO', 1:'GFH_TYPE_BL_INFO',
            2:'GFH_TYPE_ANTI_CLONE', 3:'GFH_TYPE_BL_SEC_KEY',
            7:'GFH_TYPE_BROM_CFG', 8:'GFH_TYPE_BROM_SEC_CFG'}
        return '('+lookup.get(val, 'unknown')+')'
    type_ = tagUint16(fp, 'type', comm)

    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct gfh_common_header')

    return {'size':size, 'type':type_}

# https://wiki.postmarketos.org/wiki/MediaTek
# except I think the length field is just a word
#
# update: it's a gfh_common_header
# https://github.com/trini/u-boot/blob/master/tools/mtk_image.h
def gfh_file_info(fp):
    start = fp.tell()

    info = gfh_common_header(fp)

    name = tag(fp, 12, 'name[12]')
    assert name == GFH_FILE_INFO_NAME + b'\x00\x00\x00'
    unused = tagUint32(fp, 'unused')

    def gen_comment0(val):
        lookup = {0:'NONE', 1:'ARM-Bootloader', 2:'ARM-External-Bootloader',
            10:'Root-Certificate', 256:'Primary-MAUI', 264:'VIVA',
            769:'SECURE_RO_ME'}
        return f'({lookup.get(val, "unknown")})'
    tagUint16(fp, 'file_type', gen_comment0)

    def gen_comment1(val):
        lookup = {0:'NONE', 1:'NOR Flash', 2:'NAND Sequential Flash',
            3:'HAND_TTBL', 4:'NAND_FDM50', 5:'EMMC-Boot-Region',
            6:'EMMC-DAta-Region', 7:'Serial Flash', 255:'Device-End'}
        return f'({lookup.get(val, "Unknown")})'
    tagUint8(fp, 'flash_type', gen_comment1)

    def gen_comment2(val):
        lookup = {0:'GFH_SIG_TYPE_NONE', 1:'GFH_SIG_TYPE_SHA256', 2:'SINGLE and PHASH',
            4: 'MULTI', 5:'TYPE_NUM', 255:'TYPE_END'}
        return f'({lookup.get(val, "Unknown")})'
    sig_type = tagUint8(fp, 'sig_type', gen_comment2)
    info['sig_type'] = sig_type

    tagUint32(fp, 'load_addr')

    total_size = tagUint32(fp, 'total_size')
    info['total_size'] = total_size

    max_size = tagUint32(fp, 'max_size')
    #assert max_size == 0x40000
    tagUint32(fp, 'hdr_size')

    def gen_comment3(val):
        return f'(starts at 0x{start + total_size - val:X})'
    sig_size = tagUint32(fp, 'sig_size', gen_comment3)
    info['sig_size'] = sig_size
    tagUint32(fp, 'jump_offset')

    def gen_comment3(val):
        result = []
        if val & 1: result.append('POST_BUILD_DONE')
        if val & 2: result.append('Execute In Place')
        return '('+'|'.join(result)+')' if result else ''
    tagUint32(fp, 'processed', gen_comment3)

    length = fp.tell() - start
    #assert length == len_header
    print(f'[0x{start:X},0x{start+length:X}) struct gfh_file_info')

    return info

def gfh_bl_info(fp):
    start = fp.tell()
    info = gfh_common_header(fp)
    tagUint32(fp, 'attr')
    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct gfh_bl_info')

    return info

def gfh_brom_cfg(fp):
    start = fp.tell()
    info = gfh_common_header(fp)

    # config bits
    def comment(val):
        result = []
        if val & GFH_BROM_CFG_USBDL_BY_AUTO_DETECT_TIMEOUT_EN:
            result.append('USBDL_BY_AUTO_DETECT_TIMEOUT_EN')
        if val & GFH_BROM_CFG_USBDL_AUTO_DETECT_DIS:
            result.append('USBDL_AUTO_DETECT_DIS')
        if val & GFH_BROM_CFG_USBDL_BY_KCOL0_TIMEOUT_EN:
            result.append('USBDL_BY_KCOL0_TIMEOUT_EN')
        if val & GFH_BROM_CFG_USBDL_BY_FLAG_TIMEOUT_EN:
            result.append('USBDL_BY_FLAG_TIMEOUT_EN')
        if val & GFH_BROM_CFG_JUMP_BL_ARM64_EN:
            result.append('JUMP_BL_ARM64_EN')
        if val & GFH_BROM_CFG_JUMP_BL_ARM64:
            result.append('JUMP_BL_ARM64')
        return '('+'|'.join(result)+')' if result else ''
    tagUint32(fp, 'cfg_bits', comment)

    tagUint32(fp, 'usbdl_by_auto_detect_timeout_ms')
    tag(fp, 0x45, 'unused')
    tagUint8(fp, 'jump_bl_arm64')
    tag(fp, 2, 'unused')
    tagUint32(fp, 'usbdl_by_kcol0_timeout_ms')
    tagUint32(fp, 'usbdl_by_flag_timeout_ms')
    tagUint32(fp, 'pad')
    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct gfh_brom_cfg')

    return info

def gfh_anti_clone(fp):
    start = fp.tell()
    info = gfh_common_header(fp)
    tagUint8(fp, 'ac_b2k')
    tagUint8(fp, 'ac_b2c')
    tagUint16(fp, 'pad')
    tagUint32(fp, 'ac_offset')
    tagUint32(fp, 'ac_len')
    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct gfh_anti_clone')

    return info

def gfh_brom_sec_cfg(fp):
    start = fp.tell()
    info = gfh_common_header(fp)
    def comment(val):
        result = []
        if val & BROM_SEC_CFG_JTAG_EN:
            result.append('BROM_SEC_CFG_JTAG_EN')
        if val & BROM_SEC_CFG_UART_EN:
            result.append('BROM_SEC_CFG_UART_EN')
        return '('+'|'.join(result)+')' if result else ''
    tagUint8(fp, 'cfg_bits', comment)
    tag(fp, 0x20, 'customer_name[0x20]')
    tagUint32(fp, 'pad')
    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct gfh_brom_sec_cfg')

    return info

def gfh_header(fp):
    # sample the common header
    sample = peek(fp, 8)
    assert sample[0:3] == GFH_HEADER_MAGIC
    type_, = struct.unpack_from('<H', sample, 6)

    mark = fp.tell()

    match type_:
        case GFH_TYPE_.FILE_INFO:
            return gfh_file_info(fp)
        case GFH_TYPE_.BL_INFO:
            return gfh_bl_info(fp)
        case GFH_TYPE_.BROM_CFG:
            return gfh_brom_cfg(fp)
        case GFH_TYPE_.ANTI_CLONE:
            return gfh_anti_clone(fp)
        case GFH_TYPE_.BROM_SEC_CFG:
            return gfh_brom_sec_cfg(fp)
        case _:
            # unknown type, read common header and skip over what it contained
            mark = fp.tell()
            info = gfh_common_header(fp)
            fp.seek(mark + info['size'])
            return info

        #case GFH_TYPE_BL_INFO:

def sig_5_entry(fp):
    start = fp.tell()

    sample = peek(fp, 4)
    assert sample[0:4] == SIG_TYPE_5_MAGIC

    tagUint32(fp, 'magic')
    tagUint32(fp, 'unknown')
    size = tagUint32(fp, 'size') # includes these headers
    tagUint32(fp, 'flags')

    data_sz = size - 16
    tag(fp, data_sz, f'data (0x{data_sz:X} bytes)')

    length = fp.tell() - start
    print(f'[0x{start:X},0x{start+length:X}) struct sig_5_entry')

