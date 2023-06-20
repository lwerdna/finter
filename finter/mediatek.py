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


