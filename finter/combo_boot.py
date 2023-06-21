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

    while True:
        if peek(fp, 3) == GFH_HEADER_MAGIC:
            gfh_header(fp)
        else:
            break
