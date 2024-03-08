#!/usr/bin/env python

# u-boot image

import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

IH_MAGIC = 0x27051956    # Image Magic Number
IH_NMLEN = 32            # Image Name Length

class image_type_t(Enum):
	IH_TYPE_INVALID		= 0	# Invalid Imageg
	IH_TYPE_STANDALONE = auto()		# Standalone Programg
	IH_TYPE_KERNEL = auto()			# OS Kernel Imageg
	IH_TYPE_RAMDISK = auto()		# RAMDisk Imageg
	IH_TYPE_MULTI = auto()			# Multi-File Imageg
	IH_TYPE_FIRMWARE = auto()		# Firmware Imageg
	IH_TYPE_SCRIPT = auto()			# Script fileg
	IH_TYPE_FILESYSTEM = auto()		# Filesystem Image (any type)g
	IH_TYPE_FLATDT = auto()			# Binary Flat Device Tree Blobg
	IH_TYPE_KWBIMAGE = auto()		# Kirkwood Boot Imageg
	IH_TYPE_IMXIMAGE = auto()		# Freescale IMXBoot Imageg
	IH_TYPE_UBLIMAGE = auto()		# Davinci UBL Imageg
	IH_TYPE_OMAPIMAGE = auto()		# TI OMAP Config Header Imageg
	IH_TYPE_AISIMAGE = auto()		# TI Davinci AIS Imageg
	# OS Kernel Image = auto() can run from any load addressg
	IH_TYPE_KERNEL_NOLOAD = auto()
	IH_TYPE_PBLIMAGE = auto()		# Freescale PBL Boot Imageg
	IH_TYPE_MXSIMAGE = auto()		# Freescale MXSBoot Imageg
	IH_TYPE_GPIMAGE = auto()		# TI Keystone GPHeader Imageg
	IH_TYPE_ATMELIMAGE = auto()		# ATMEL ROM bootable Imageg
	IH_TYPE_SOCFPGAIMAGE = auto()		# Altera SOCFPGA CV/AV Preloaderg
	IH_TYPE_X86_SETUP = auto()		# x86 setup.bin Imageg
	IH_TYPE_LPC32XXIMAGE = auto()		# x86 setup.bin Imageg
	IH_TYPE_LOADABLE = auto()		# A list of typeless imagesg
	IH_TYPE_RKIMAGE = auto()		# Rockchip Boot Imageg
	IH_TYPE_RKSD = auto()			# Rockchip SD cardg
	IH_TYPE_RKSPI = auto()			# Rockchip SPI imageg
	IH_TYPE_ZYNQIMAGE = auto()		# Xilinx Zynq Boot Imageg
	IH_TYPE_ZYNQMPIMAGE = auto()		# Xilinx ZynqMP Boot Imageg
	IH_TYPE_ZYNQMPBIF = auto()		# Xilinx ZynqMP Boot Image (bif)g
	IH_TYPE_FPGA = auto()			# FPGA Imageg
	IH_TYPE_VYBRIDIMAGE = auto()	# VYBRID .vyb Imageg
	IH_TYPE_TEE = auto()            # Trusted Execution Environment OS Imageg
	IH_TYPE_FIRMWARE_IVT = auto()		# Firmware Image with HABv4 IVTg
	IH_TYPE_PMMC = auto()            # TI Power Management Micro-Controller Firmwareg
	IH_TYPE_STM32IMAGE = auto()		# STMicroelectronics STM32 Imageg
	IH_TYPE_SOCFPGAIMAGE_V1 = auto()	# Altera SOCFPGA A10 Preloaderg
	IH_TYPE_MTKIMAGE = auto()		# MediaTek BootROM loadable Imageg
	IH_TYPE_IMX8MIMAGE = auto()		# Freescale IMX8MBoot Imageg
	IH_TYPE_IMX8IMAGE = auto()		# Freescale IMX8Boot Imageg
	IH_TYPE_COPRO = auto()			# Coprocessor Image for remoteproc*/
	IH_TYPE_SUNXI_EGON = auto()		# Allwinner eGON Boot Imageg
	IH_TYPE_SUNXI_TOC0 = auto()		# Allwinner TOC0 Boot Imageg
	IH_TYPE_FDT_LEGACY = auto()		# Binary Flat Device Tree Blob	in a Legacy Imageg
	IH_TYPE_RENESAS_SPKG = auto()	# Renesas SPKG imageg
	IH_TYPE_STARFIVE_SPL = auto()	# StarFive SPL imageg

	IH_TYPE_COUNT = auto()			# Number of image typesg

###############################################################################
# "main"
###############################################################################

SIZEOF_IMAGE_HEADER = 64

# https://github.com/u-boot/u-boot/blob/master/include/image.h

def analyze(fp):
    setBigEndian()

    if uint32(fp, 1) != IH_MAGIC:
        return

    tag(fp, SIZEOF_IMAGE_HEADER, 'image_header', 1)

    tagUint32(fp, 'ih_magic')
    tagUint32(fp, 'ih_hcrc')
    tagUint32(fp, 'ih_time')
    tagUint32(fp, 'ih_size')
    tagUint32(fp, 'ih_load')
    tagUint32(fp, 'ih_ep')
    tagUint32(fp, 'ih_dcrc')

    tagUint8(fp, 'ih_os')
    tagUint8(fp, 'ih_arch')
    tagUint8(fp, 'ih_type', lambda x: enum_int_to_name(image_type_t, x))
    tagUint8(fp, 'ih_comp')
    tag(fp, IH_NMLEN, f'ih_name[{IH_NMLEN}]')

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
