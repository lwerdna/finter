from .helpers import *

# BRLYT = "BootRom LaYouT"
BRLYT_NAME = b"BRLYT"
BRLYT_MAGIC = b"\x42\x42\x42\x42"

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

# https://wiki.postmarketos.org/wiki/MediaTek
# except I think the length field is just a word
def file_info_image(fp):
    start = fp.tell()

    magic = tag(fp, 4, 'magic0')
    assert magic == b'\x4d\x4d\x4d\x01'
    len_header = tagUint16(fp, 'length (of complete header)')
    tagUint16(fp, 'unknown')
    magic = tag(fp, 12, 'magic1')
    assert magic == b'FILE_INFO\x00\x00\x00'
    magic = tagUint32(fp, 'magic2')
    assert magic == 1

    def gen_comment0(val):
        lookup = {0:'NONE', 1:'ARM-Bootloader', 2:'ARM-External-Bootloader',
            10:'Root-Certificate', 256:'Primary-MAUI', 264:'VIVA',
            769:'SECURE_RO_ME'}
        return f'({lookup.get(val, "Unknown")})'
    tagUint16(fp, 'image_type', gen_comment0)

    def gen_comment1(val):
        lookup = {0:'NONE', 1:'NOR Flash', 2:'NAND Sequential Flash',
            3:'HAND_TTBL', 4:'NAND_FDM50', 5:'EMMC-Boot-Region',
            6:'EMMC-DAta-Region', 7:'Serial Flash', 255:'Device-End'}
        return f'({lookup.get(val, "Unknown")})'
    tagUint8(fp, 'storage_type', gen_comment1)

    def gen_comment2(val):
        lookup = {0:'No Signature', 1:'PHASH', 2:'SINGLE and PHASH',
            4: 'MULTI', 5:'TYPE_NUM', 255:'TYPE_END'}
        return f'({lookup.get(val, "Unknown")})'
    tagUint8(fp, 'signature_type', gen_comment2)

    tagUint32(fp, 'load_address')
    tagUint32(fp, 'total_file_sz')
    max_file_sz = tagUint32(fp, 'max_file_sz')
    #assert max_file_sz == 0x40000
    tagUint32(fp, 'content_offset')
    tagUint32(fp, 'signature_length')
    tagUint32(fp, 'jump_offset')

    def gen_comment3(val):
        result = []
        if val & 1: result.append('POST_BUILD_DONE')
        if val & 2: result.append('Execute In Place')
        return '('+'|'.join(result)+')' if result else ''
    tagUint32(fp, 'ending', gen_comment3)

    length = fp.tell() - start
    assert length == len_header
    print(f'[0x{start:X},0x{start+length:X}) struct file_info_image')
