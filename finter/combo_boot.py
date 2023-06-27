#!/usr/bin/env python

# links:
# https://github.com/u-boot/u-boot/blob/master/tools/mtk_image.h
# https://github.com/u-boot/u-boot/blob/master/tools/mtk_image.c
# https://coral.googlesource.com/uboot-imx/+/refs/heads/4.19_enterprise_staging/tools/mtk_image.h

import sys
import struct
import binascii

from .helpers import *
from .mediatek import *

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    if not peek(fp, 12) == b'COMBO_BOOT\x00\x00':
        return

    gen_device_header(fp)

    o_sig_type_5 = None

    while True:
        anchor = fp.tell()

        if peek(fp, 3) != GFH_HEADER_MAGIC:
            break

        info = gfh_header(fp)

        if info['type'] == GFH_TYPE_.FILE_INFO:
            if info['sig_type'] == 5 and info['sig_size']:
                o_sig_type_5 = anchor + info['total_size'] - info['sig_size']

    if o_sig_type_5:
        fp.seek(o_sig_type_5)

        num_entries, = struct.unpack('<I', fp.read(4))

        for i in range(num_entries):
            sig_5_entry(fp)
