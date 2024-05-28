#!/usr/bin/env python

# u-boot image
# https://github.com/u-boot/u-boot/blob/master/include/image.h

import sys
import struct
import binascii
from enum import Enum, auto

from .helpers import *

IH_MAGIC = 0x27051956    # Image Magic Number
IH_NMLEN = 32            # Image Name Length

class ih_os(Enum):
	IH_OS_INVALID = 0 # /* Invalid OS	*/
	IH_OS_OPENBSD = auto() # /* OpenBSD	*/
	IH_OS_NETBSD = auto() # /* NetBSD	*/
	IH_OS_FREEBSD = auto() # /* FreeBSD	*/
	IH_OS_4_4BSD = auto() # /* 4.4BSD	*/
	IH_OS_LINUX = auto() # /* Linux	*/
	IH_OS_SVR4 = auto() # /* SVR4		*/
	IH_OS_ESIX = auto() # /* Esix		*/
	IH_OS_SOLARIS = auto() # /* Solaris	*/
	IH_OS_IRIX = auto() # /* Irix		*/
	IH_OS_SCO = auto() # /* SCO		*/
	IH_OS_DELL = auto() # /* Dell		*/
	IH_OS_NCR = auto() # /* NCR		*/
	IH_OS_LYNXOS = auto() # /* LynxOS	*/
	IH_OS_VXWORKS = auto() # /* VxWorks	*/
	IH_OS_PSOS = auto() # /* pSOS		*/
	IH_OS_QNX = auto() # /* QNX		*/
	IH_OS_U_BOOT = auto() # /* Firmware	*/
	IH_OS_RTEMS = auto() # /* RTEMS	*/
	IH_OS_ARTOS = auto() # /* ARTOS	*/
	IH_OS_UNITY = auto() # /* Unity OS	*/
	IH_OS_INTEGRITY = auto() # /* INTEGRITY	*/
	IH_OS_OSE = auto() # /* OSE		*/
	IH_OS_PLAN9 = auto() # /* Plan 9	*/
	IH_OS_OPENRTOS = auto() # /* OpenRTOS	*/
	IH_OS_ARM_TRUSTED_FIRMWARE = auto() # /* ARM Trusted Firmware */
	IH_OS_TEE = auto() # /* Trusted Execution Environment */
	IH_OS_OPENSBI = auto() # /* RISC-V OpenSBI */
	IH_OS_EFI = auto() # /* EFI Firmware (e.g. GRUB2) */

class ih_arch(Enum):
	IH_ARCH_INVALID	= 0 # /* Invalid CPU	*/
	IH_ARCH_ALPHA = auto() # /* Alpha	*/
	IH_ARCH_ARM = auto() # /* ARM		*/
	IH_ARCH_I386 = auto() # /* Intel x86	*/
	IH_ARCH_IA64 = auto() # /* IA64		*/
	IH_ARCH_MIPS = auto() # /* MIPS		*/
	IH_ARCH_MIPS64 = auto() # /* MIPS	 64 Bit */
	IH_ARCH_PPC = auto() # /* PowerPC	*/
	IH_ARCH_S390 = auto() # /* IBM S390	*/
	IH_ARCH_SH = auto() # /* SuperH	*/
	IH_ARCH_SPARC = auto() # /* Sparc	*/
	IH_ARCH_SPARC64 = auto() # /* Sparc 64 Bit */
	IH_ARCH_M68K = auto() # /* M68K		*/
	IH_ARCH_NIOS = auto() # /* Nios-32	*/
	IH_ARCH_MICROBLAZE = auto() # /* MicroBlaze   */
	IH_ARCH_NIOS2 = auto() # /* Nios-II	*/
	IH_ARCH_BLACKFIN = auto() # /* Blackfin	*/
	IH_ARCH_AVR32 = auto() # /* AVR32	*/
	IH_ARCH_ST200 = auto() # /* STMicroelectronics ST200  */
	IH_ARCH_SANDBOX = auto() # /* Sandbox architecture (test only) */
	IH_ARCH_NDS32 = auto() # /* ANDES Technology - NDS32  */
	IH_ARCH_OPENRISC = auto() # /* OpenRISC 1000  */
	IH_ARCH_ARM64 = auto() # /* ARM64	*/
	IH_ARCH_ARC = auto() # /* Synopsys DesignWare ARC */
	IH_ARCH_X86_64 = auto() # /* AMD x86_64, Intel and Via */
	IH_ARCH_XTENSA = auto() # /* Xtensa	*/
	IH_ARCH_RISCV = auto() # /* RISC-V */

class image_type_t(Enum):
	IH_TYPE_INVALID	= 0	# Invalid Image
	IH_TYPE_STANDALONE = auto()		# Standalone Program
	IH_TYPE_KERNEL = auto()			# OS Kernel Image
	IH_TYPE_RAMDISK = auto()		# RAMDisk Image
	IH_TYPE_MULTI = auto()			# Multi-File Image
	IH_TYPE_FIRMWARE = auto()		# Firmware Image
	IH_TYPE_SCRIPT = auto()			# Script file
	IH_TYPE_FILESYSTEM = auto()		# Filesystem Image (any type)
	IH_TYPE_FLATDT = auto()			# Binary Flat Device Tree Blob
	IH_TYPE_KWBIMAGE = auto()		# Kirkwood Boot Image
	IH_TYPE_IMXIMAGE = auto()		# Freescale IMXBoot Image
	IH_TYPE_UBLIMAGE = auto()		# Davinci UBL Image
	IH_TYPE_OMAPIMAGE = auto()		# TI OMAP Config Header Image
	IH_TYPE_AISIMAGE = auto()		# TI Davinci AIS Image
	# OS Kernel Image = auto() can run from any load address
	IH_TYPE_KERNEL_NOLOAD = auto()
	IH_TYPE_PBLIMAGE = auto()		# Freescale PBL Boot Image
	IH_TYPE_MXSIMAGE = auto()		# Freescale MXSBoot Image
	IH_TYPE_GPIMAGE = auto()		# TI Keystone GPHeader Image
	IH_TYPE_ATMELIMAGE = auto()		# ATMEL ROM bootable Image
	IH_TYPE_SOCFPGAIMAGE = auto()		# Altera SOCFPGA CV/AV Preloader
	IH_TYPE_X86_SETUP = auto()		# x86 setup.bin Image
	IH_TYPE_LPC32XXIMAGE = auto()		# x86 setup.bin Image
	IH_TYPE_LOADABLE = auto()		# A list of typeless images
	IH_TYPE_RKIMAGE = auto()		# Rockchip Boot Image
	IH_TYPE_RKSD = auto()			# Rockchip SD card
	IH_TYPE_RKSPI = auto()			# Rockchip SPI image
	IH_TYPE_ZYNQIMAGE = auto()		# Xilinx Zynq Boot Image
	IH_TYPE_ZYNQMPIMAGE = auto()		# Xilinx ZynqMP Boot Image
	IH_TYPE_ZYNQMPBIF = auto()		# Xilinx ZynqMP Boot Image (bif)
	IH_TYPE_FPGA = auto()			# FPGA Image
	IH_TYPE_VYBRIDIMAGE = auto()	# VYBRID .vyb Image
	IH_TYPE_TEE = auto()            # Trusted Execution Environment OS Image
	IH_TYPE_FIRMWARE_IVT = auto()		# Firmware Image with HABv4 IVT
	IH_TYPE_PMMC = auto()            # TI Power Management Micro-Controller Firmware
	IH_TYPE_STM32IMAGE = auto()		# STMicroelectronics STM32 Image
	IH_TYPE_SOCFPGAIMAGE_V1 = auto()	# Altera SOCFPGA A10 Preloader
	IH_TYPE_MTKIMAGE = auto()		# MediaTek BootROM loadable Image
	IH_TYPE_IMX8MIMAGE = auto()		# Freescale IMX8MBoot Image
	IH_TYPE_IMX8IMAGE = auto()		# Freescale IMX8Boot Image
	IH_TYPE_COPRO = auto()			# Coprocessor Image for remoteproc*/
	IH_TYPE_SUNXI_EGON = auto()		# Allwinner eGON Boot Image
	IH_TYPE_SUNXI_TOC0 = auto()		# Allwinner TOC0 Boot Image
	IH_TYPE_FDT_LEGACY = auto()		# Binary Flat Device Tree Blob	in a Legacy Image
	IH_TYPE_RENESAS_SPKG = auto()	# Renesas SPKG image
	IH_TYPE_STARFIVE_SPL = auto()	# StarFive SPL image

class ih_comp(Enum):
	IH_COMP_NONE = 0 # /*  No	 Compression Used	*/
	IH_COMP_GZIP = auto() # /* gzip	 Compression Used	*/
	IH_COMP_BZIP2 = auto() # /* bzip2 Compression Used	*/
	IH_COMP_LZMA = auto() # /* lzma  Compression Used	*/
	IH_COMP_LZO = auto() # /* lzo   Compression Used	*/
	IH_COMP_LZ4 = auto() # /* lz4   Compression Used	*/
	IH_COMP_ZSTD = auto() # /* zstd   Compression Used	*/

###############################################################################
# "main"
###############################################################################

SIZEOF_IMAGE_HEADER = 64


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

    tagUint8(fp, 'ih_os', lambda x: enum_int_to_name(ih_os, x))
    tagUint8(fp, 'ih_arch', lambda x: enum_int_to_name(ih_arch, x))
    tagUint8(fp, 'ih_type', lambda x: enum_int_to_name(image_type_t, x))
    tagUint8(fp, 'ih_comp', lambda x: enum_int_to_name(ih_comp, x))
    tag(fp, IH_NMLEN, f'ih_name[{IH_NMLEN}]')

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
