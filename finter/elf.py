#!/usr/bin/env python

import sys
import struct
import binascii

from enum import Enum, auto, unique

from .helpers import *

EI_NIDENT = 16
ELFMAG = '\x7FELF'

ELFLCASSNONE = 0
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFCLASSNUM = 3

ELFDATANONE = 0
ELFDATA2LSB = 1
ELFDATA2MSB = 2
def ei_data_tostr(t):
    lookup = { ELFDATANONE:'NONE', ELFDATA2LSB:'LSB (little-end)',
        ELFDATA2MSB:'MSB (big-end)' }

    if t in lookup:
        return lookup[t]
    else:
        return 'UNKNOWN'

ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_LOCPROC = 0xFF00
ET_HIPROC = 0xFFFF
def e_type_tostr(t):
    lookup = ['ET_NONE', 'ET_REL', 'ET_EXEC', 'ET_DYN', 'ET_CORE']
    if t >= 0 and t < len(lookup):
        return lookup[t]
    return 'UNKNOWN'

EV_NONE = 0
EV_CURRENT = 1
EV_NUM = 2

SIZE_ELF32_HDR = 0x34
SIZE_ELF32_PHDR = 0x20
SIZE_ELF32_SHDR = 0x28
SIZE_ELF32_SYM = 0x10
SIZE_ELF32_DYN = 0x8

SIZE_ELF64_HDR = 0x40
SIZE_ELF64_PHDR = 0x38
SIZE_ELF64_SHDR = 0x40
SIZE_ELF64_SYM = 0x18
SIZE_ELF64_DYN = 0x10

# machine types
class E_MACHINE(Enum):
    EM_NONE = 0    #  No machine
    EM_M32 = 1    #  AT&T WE 32100
    EM_SPARC = 2    #  SUN SPARC
    EM_386 = 3    #  Intel 80386
    EM_68K = 4    #  Motorola m68k family
    EM_88K = 5    #  Motorola m88k family
    EM_IAMCU = 6    #  Intel MCU
    EM_860 = 7    #  Intel 80860
    EM_MIPS = 8    #  MIPS R3000 big-endian
    EM_S370 = 9    #  IBM System/370
    EM_MIPS_RS3_LE = 10    #  MIPS R3000 little-endian
    EM_PARISC = 15    #  HPPA
    EM_VPP500 = 17    #  Fujitsu VPP500
    EM_SPARC32PLUS = 18    #  Sun's "v8plus"
    EM_960 = 19    #  Intel 80960
    EM_PPC = 20    #  PowerPC
    EM_PPC64 = 21    #  PowerPC 64-bit
    EM_S390 = 22    #  IBM S390
    EM_SPU = 23    #  IBM SPU/SPC
    EM_V800 = 36    #  NEC V800 series
    EM_FR20 = 37    #  Fujitsu FR20
    EM_RH32 = 38    #  TRW RH-32
    EM_RCE = 39    #  Motorola RCE
    EM_ARM = 40    #  ARM
    EM_FAKE_ALPHA = 41    #  Digital Alpha
    EM_SH = 42    #  Hitachi SH
    EM_SPARCV9 = 43    #  SPARC v9 64-bit
    EM_TRICORE = 44    #  Siemens Tricore
    EM_ARC = 45    #  Argonaut RISC Core
    EM_H8_300 = 46    #  Hitachi H8/300
    EM_H8_300H = 47    #  Hitachi H8/300H
    EM_H8S = 48    #  Hitachi H8S
    EM_H8_500 = 49    #  Hitachi H8/500
    EM_IA_64 = 50    #  Intel Merced
    EM_MIPS_X = 51    #  Stanford MIPS-X
    EM_COLDFIRE = 52    #  Motorola Coldfire
    EM_68HC12 = 53    #  Motorola M68HC12
    EM_MMA = 54    #  Fujitsu MMA Multimedia Accelerator
    EM_PCP = 55    #  Siemens PCP
    EM_NCPU = 56    #  Sony nCPU embeeded RISC
    EM_NDR1 = 57    #  Denso NDR1 microprocessor
    EM_STARCORE = 58    #  Motorola Start*Core processor
    EM_ME16 = 59    #  Toyota ME16 processor
    EM_ST100 = 60    #  STMicroelectronic ST100 processor
    EM_TINYJ = 61    #  Advanced Logic Corp. Tinyj emb.fam
    EM_X86_64 = 62    #  AMD x86-64 architecture
    EM_PDSP = 63    #  Sony DSP Processor
    EM_PDP10 = 64    #  Digital PDP-10
    EM_PDP11 = 65    #  Digital PDP-11
    EM_FX66 = 66    #  Siemens FX66 microcontroller
    EM_ST9PLUS = 67    #  STMicroelectronics ST9+ 8/16 mc
    EM_ST7 = 68    #  STmicroelectronics ST7 8 bit mc
    EM_68HC16 = 69    #  Motorola MC68HC16 microcontroller
    EM_68HC11 = 70    #  Motorola MC68HC11 microcontroller
    EM_68HC08 = 71    #  Motorola MC68HC08 microcontroller
    EM_68HC05 = 72    #  Motorola MC68HC05 microcontroller
    EM_SVX = 73    #  Silicon Graphics SVx
    EM_ST19 = 74    #  STMicroelectronics ST19 8 bit mc
    EM_VAX = 75    #  Digital VAX
    EM_CRIS = 76    #  Axis Communications 32-bit emb.proc
    EM_JAVELIN = 77    #  Infineon Technologies 32-bit emb.proc
    EM_FIREPATH = 78    #  Element 14 64-bit DSP Processor
    EM_ZSP = 79    #  LSI Logic 16-bit DSP Processor
    EM_MMIX = 80    #  Donald Knuth's educational 64-bit proc
    EM_HUANY = 81    #  Harvard University machine-independent object files
    EM_PRISM = 82    #  SiTera Prism
    EM_AVR = 83    #  Atmel AVR 8-bit microcontroller
    EM_FR30 = 84    #  Fujitsu FR30
    EM_D10V = 85    #  Mitsubishi D10V
    EM_D30V = 86    #  Mitsubishi D30V
    EM_V850 = 87    #  NEC v850
    EM_M32R = 88    #  Mitsubishi M32R
    EM_MN10300 = 89    #  Matsushita MN10300
    EM_MN10200 = 90    #  Matsushita MN10200
    EM_PJ = 91    #  picoJava
    EM_OPENRISC = 92    #  OpenRISC 32-bit embedded processor
    EM_ARC_COMPACT = 93    #  ARC International ARCompact
    EM_XTENSA = 94    #  Tensilica Xtensa Architecture
    EM_VIDEOCORE = 95    #  Alphamosaic VideoCore
    EM_TMM_GPP = 96    #  Thompson Multimedia General Purpose Proc
    EM_NS32K = 97    #  National Semi. 32000
    EM_TPC = 98    #  Tenor Network TPC
    EM_SNP1K = 99    #  Trebia SNP 1000
    EM_ST200 = 100    #  STMicroelectronics ST200
    EM_IP2K = 101    #  Ubicom IP2xxx
    EM_MAX = 102    #  MAX processor
    EM_CR = 103    #  National Semi. CompactRISC
    EM_F2MC16 = 104    #  Fujitsu F2MC16
    EM_MSP430 = 105    #  Texas Instruments msp430
    EM_BLACKFIN = 106    #  Analog Devices Blackfin DSP
    EM_SE_C33 = 107    #  Seiko Epson S1C33 family
    EM_SEP = 108    #  Sharp embedded microprocessor
    EM_ARCA = 109    #  Arca RISC
    EM_UNICORE = 110    #  PKU-Unity & MPRC Peking Uni. mc series
    EM_EXCESS = 111    #  eXcess configurable cpu
    EM_DXP = 112    #  Icera Semi. Deep Execution Processor
    EM_ALTERA_NIOS2 = 113    #  Altera Nios II
    EM_CRX = 114    #  National Semi. CompactRISC CRX
    EM_XGATE = 115    #  Motorola XGATE
    EM_C166 = 116    #  Infineon C16x/XC16x
    EM_M16C = 117    #  Renesas M16C
    EM_DSPIC30F = 118    #  Microchip Technology dsPIC30F
    EM_CE = 119    #  Freescale Communication Engine RISC
    EM_M32C = 120    #  Renesas M32C
    EM_TSK3000 = 131    #  Altium TSK3000
    EM_RS08 = 132    #  Freescale RS08
    EM_SHARC = 133    #  Analog Devices SHARC family
    EM_ECOG2 = 134    #  Cyan Technology eCOG2
    EM_SCORE7 = 135    #  Sunplus S+core7 RISC
    EM_DSP24 = 136    #  New Japan Radio (NJR) 24-bit DSP
    EM_VIDEOCORE3 = 137    #  Broadcom VideoCore III
    EM_LATTICEMICO32 = 138    #  RISC for Lattice FPGA
    EM_SE_C17 = 139    #  Seiko Epson C17
    EM_TI_C6000 = 140    #  Texas Instruments TMS320C6000 DSP
    EM_TI_C2000 = 141    #  Texas Instruments TMS320C2000 DSP
    EM_TI_C5500 = 142    #  Texas Instruments TMS320C55x DSP
    EM_TI_ARP32 = 143    #  Texas Instruments App. Specific RISC
    EM_TI_PRU = 144    #  Texas Instruments Prog. Realtime Unit
    EM_MMDSP_PLUS = 160    #  STMicroelectronics 64bit VLIW DSP
    EM_CYPRESS_M8C = 161    #  Cypress M8C
    EM_R32C = 162    #  Renesas R32C
    EM_TRIMEDIA = 163    #  NXP Semi. TriMedia
    EM_QDSP6 = 164    #  QUALCOMM DSP6
    EM_8051 = 165    #  Intel 8051 and variants
    EM_STXP7X = 166    #  STMicroelectronics STxP7x
    EM_NDS32 = 167    #  Andes Tech. compact code emb. RISC
    EM_ECOG1X = 168    #  Cyan Technology eCOG1X
    EM_MAXQ30 = 169    #  Dallas Semi. MAXQ30 mc
    EM_XIMO16 = 170    #  New Japan Radio (NJR) 16-bit DSP
    EM_MANIK = 171    #  M2000 Reconfigurable RISC
    EM_CRAYNV2 = 172    #  Cray NV2 vector architecture
    EM_RX = 173    #  Renesas RX
    EM_METAG = 174    #  Imagination Tech. META
    EM_MCST_ELBRUS = 175    #  MCST Elbrus
    EM_ECOG16 = 176    #  Cyan Technology eCOG16
    EM_CR16 = 177    #  National Semi. CompactRISC CR16
    EM_ETPU = 178    #  Freescale Extended Time Processing Unit
    EM_SLE9X = 179    #  Infineon Tech. SLE9X
    EM_L10M = 180    #  Intel L10M
    EM_K10M = 181    #  Intel K10M
    EM_AARCH64 = 183    #  ARM AARCH64
    EM_AVR32 = 185    #  Amtel 32-bit microprocessor
    EM_STM8 = 186    #  STMicroelectronics STM8
    EM_TILE64 = 187    #  Tileta TILE64
    EM_TILEPRO = 188    #  Tilera TILEPro
    EM_MICROBLAZE = 189    #  Xilinx MicroBlaze
    EM_CUDA = 190    #  NVIDIA CUDA
    EM_TILEGX = 191    #  Tilera TILE-Gx
    EM_CLOUDSHIELD = 192    #  CloudShield
    EM_COREA_1ST = 193    #  KIPO-KAIST Core-A 1st gen.
    EM_COREA_2ND = 194    #  KIPO-KAIST Core-A 2nd gen.
    EM_ARC_COMPACT2 = 195    #  Synopsys ARCompact V2
    EM_OPEN8 = 196    #  Open8 RISC
    EM_RL78 = 197    #  Renesas RL78
    EM_VIDEOCORE5 = 198    #  Broadcom VideoCore V
    EM_78KOR = 199    #  Renesas 78KOR
    EM_56800EX = 200    #  Freescale 56800EX DSC
    EM_BA1 = 201    #  Beyond BA1
    EM_BA2 = 202    #  Beyond BA2
    EM_XCORE = 203    #  XMOS xCORE
    EM_MCHP_PIC = 204    #  Microchip 8-bit PIC(r)
    EM_KM32 = 210    #  KM211 KM32
    EM_KMX32 = 211    #  KM211 KMX32
    EM_EMX16 = 212    #  KM211 KMX16
    EM_EMX8 = 213    #  KM211 KMX8
    EM_KVARC = 214    #  KM211 KVARC
    EM_CDP = 215    #  Paneve CDP
    EM_COGE = 216    #  Cognitive Smart Memory Processor
    EM_COOL = 217    #  Bluechip CoolEngine
    EM_NORC = 218    #  Nanoradio Optimized RISC
    EM_CSR_KALIMBA = 219    #  CSR Kalimba
    EM_Z80 = 220    #  Zilog Z80
    EM_VISIUM = 221    #  Controls and Data Services VISIUMcore
    EM_FT32 = 222    #  FTDI Chip FT32
    EM_MOXIE = 223    #  Moxie processor
    EM_AMDGPU = 224    #  AMD GPU
    EM_RISCV = 243    #  RISC-V
    EM_BPF = 247    #  Linux BPF -- in-kernel virtual machine
    EM_CSKY = 252     #  C-SKY

def e_machine_tostr(em):
	try:
		name = E_MACHINE(em).name
	except ValueError:
		name = '(UNKNOWN %d)' % (em, em)
	return name

# section header type
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP = 17
SHT_SYMTAB_SHNDX = 18
SHT_NUM = 19
SHT_GNU_ATTRIBUTES = 0x6ffffff5
SHT_GNU_HASH = 0x6ffffff6
SHT_GNU_LIBLIST = 0x6ffffff7
SHT_CHECKSUM = 0x6ffffff8
SHT_SUNW_move = 0x6ffffffa
SHT_SUNW_COMDAT = 0x6ffffffb
SHT_SUNW_syminfo = 0x6ffffffc
SHT_GNU_verdef = 0x6ffffffd
SHT_GNU_verneed = 0x6ffffffe
SHT_GNU_versym = 0x6fffffff
SHT_LOOS = 0x60000000
SHT_HIOS = 0x6fffffff
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7FFFFFFF
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0xFFFFFFFF
def sh_type_tostr(t):
    lookup = {
        SHT_NULL:'NULL', SHT_PROGBITS:'PROGBITS', SHT_SYMTAB:'SYMTAB',
        SHT_STRTAB:'STRTAB', SHT_RELA:'RELA', SHT_HASH:'HASH',
        SHT_DYNAMIC:'DYNAMIC', SHT_NOTE:'NOTE', SHT_NOBITS:'NOBITS',
        SHT_REL:'REL', SHT_SHLIB:'SHLIB', SHT_DYNSYM:'DYNSYM',
        SHT_INIT_ARRAY:'INIT_ARRAY', SHT_FINI_ARRAY:'FINI_ARRAY', SHT_PREINIT_ARRAY:'PREINIT_ARRAY',
        SHT_GROUP:'GROUP', SHT_SYMTAB_SHNDX:'SYMTAB_SHNDX', SHT_NUM:'NUM',
        SHT_GNU_ATTRIBUTES:'GNU_ATTRIBUTES', SHT_GNU_HASH:'GNU_HASH', SHT_GNU_LIBLIST:'GNU_LIBLIST',
        SHT_CHECKSUM:'CHECKSUM', SHT_SUNW_move:'SUNW_move', SHT_SUNW_COMDAT:'SUNW_COMDAT',
        SHT_SUNW_syminfo:'SUNW_syminfo', SHT_GNU_verdef:'GNU_verdef', SHT_GNU_verneed:'GNU_verneed',
        SHT_GNU_versym:'GNU_versym'
    }
    if t in lookup:
        return lookup[t]
    if t >= SHT_LOOS and t <= SHT_HIOS:
        return 'OS'
    if t >= SHT_LOPROC and t <= SHT_HIPROC:
        return 'PROC'
    if t >= SHT_LOUSER and t <= SHT_HIUSER:
        return 'USER'
    return 'UNKNOWN'

SHF_WRITE = (1 << 0)
SHF_ALLOC = (1 << 1)
SHF_EXECINSTR = (1 << 2)
SHF_MERGE = (1 << 4)
SHF_STRINGS = (1 << 5)
SHF_INFO_LINK = (1 << 6)
SHF_LINK_ORDER = (1 << 7)
SHF_OS_NONCONFORMING = (1 << 8)
SHF_GROUP = (1 << 9)
SHF_TLS = (1 << 10)
def sh_flags_tostr(a):
    lookup = {
        SHF_WRITE:'WRITE', SHF_ALLOC:'ALLOC', SHF_EXECINSTR:'EXECINSTR',
        SHF_MERGE:'MERGE', SHF_STRINGS:'STRINGS', SHF_INFO_LINK:'INFO_LINK',
        SHF_LINK_ORDER:'LINK_ORDER', SHF_OS_NONCONFORMING:'OS_NONCONFORMING',
        SHF_GROUP:'GROUP', SHF_TLS:'TLS'
    }
    result = []
    for bit in lookup.keys():
        if a & bit:
            result.append(lookup[bit])
    if not result:
        if a==0:
            result = ['0']
        else:
            result = 'UNKNOWN'
    return '|'.join(result)

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_LOOS = 0x60000000
PT_HIOS = 0x6fffffff
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff
PT_GNU_EH_FRAME = 0x6474e550
def phdr_type_tostr(x):
    lookup = {PT_NULL:"PT_NULL", PT_LOAD:"PT_LOAD", PT_DYNAMIC:"PT_DYNAMIC",
        PT_INTERP:"PT_INTERP", PT_NOTE:"PT_NOTE", PT_SHLIB:"PT_SHLIB",
        PT_PHDR:"PT_PHDR", PT_TLS:"PT_TLS"
    }
    if x in lookup:
        return lookup[x]
    if x >= PT_LOOS and x <= PT_HIOS:
        return 'OS'
    if x >= SHT_LOPROC and x <= SHT_HIPROC:
        strType = 'PROC'
    return 'UNKNOWN'

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_LOOS = 0x60000000
DT_HIOS = 0x6FFFFFFF
DT_LOPROC = 0x70000000
DT_HIPROC = 0x7FFFFFFF
def dynamic_type_tostr(x):
    lookup = { DT_NULL:"NULL", DT_NEEDED:"NEEDED", DT_PLTRELSZ:"PLTRELSZ",
        DT_PLTGOT:"PLTGOT", DT_HASH:"HASH", DT_STRTAB:"STRTAB",
        DT_SYMTAB:"SYMTAB", DT_RELA:"RELA", DT_RELASZ:"RELASZ",
        DT_RELAENT:"RELAENT", DT_STRSZ:"STRSZ", DT_SYMENT:"SYMENT",
        DT_INIT:"INIT", DT_FINI:"FINI", DT_SONAME:"SONAME",
        DT_RPATH:"RPATH", DT_SYMBOLIC:"SYMBOLIC", DT_REL:"REL",
        DT_RELSZ:"RELSZ", DT_RELENT:"RELENT", DT_PLTREL:"PLTREL",
        DT_DEBUG:"DEBUG", DT_TEXTREL:"TEXTREL", DT_JMPREL:"JMPREL",
        DT_BIND_NOW:"BIND_NOW", DT_INIT_ARRAY:"INIT_ARRAY", DT_FINI_ARRAY:"FINI_ARRAY",
        DT_INIT_ARRAYSZ:"INIT_ARRAYSZ", DT_FINI_ARRAYSZ:"FINI_ARRAYSZ"
    }
    if x in lookup:
        return lookup[x]
    if x >= DT_LOOS and x <= DT_HIOS:
        return "OS"
    if x >= DT_LOPROC and x <= DT_HIPROC:
        return "PROC"
    return 'UNKNOWN'

# symbol bindings
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_LOPROC = 13
STB_HIPROC = 15
def symbol_binding_tostr(x):
    lookup = { STB_LOCAL:"LOCAL", STB_GLOBAL:"GLOBAL",
        STB_WEAK:"WEAK"
    }
    if x in lookup:
        return lookup[x]
    if x >= STB_LOPROC and x <= STB_HIPROC:
        return "PROC"
    return 'UNKNOWN'

# symbol types
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6
STT_LOPROC = 13
STT_HIPROC = 15
def symbol_type_tostr(x):
    lookup = { STT_NOTYPE:"NOTYPE", STT_OBJECT:"OBJECT",
        STT_FUNC:"FUNC", STT_SECTION:"SECTION", STT_FILE:"FILE",
        STT_COMMON:"COMMON", STT_TLS:"TLS"}
    if x in lookup:
        return lookup[x]
    if x >= STT_LOPROC and x <= STT_HIPROC:
        return "PROC"
    return 'UNKNOWN'

class RELOC_TYPE_ARM(Enum):
    R_ARM_NONE = 0
    R_ARM_PC24 = 1
    R_ARM_ABS32 = 2
    R_ARM_REL32 = 3
    R_ARM_LDR_PC_G0 = 4
    R_ARM_ABS16 = 5
    R_ARM_ABS12 = 6
    R_ARM_THM_ABS5 = 7
    R_ARM_ABS8 = 8
    R_ARM_SBREL32 = 9
    R_ARM_THM_CALL = 10
    R_ARM_THM_PC8 = 11
    R_ARM_BREL_ADJ = 12
    R_ARM_TLS_DESC = 13
    R_ARM_THM_SWI8 = 14
    R_ARM_XPC25 = 15
    R_ARM_THM_XPC22 = 16
    R_ARM_TLS_DTPMOD32 = 17
    R_ARM_TLS_DTPOFF32 = 18
    R_ARM_TLS_TPOFF32 = 19
    R_ARM_COPY = 20
    R_ARM_GLOB_DAT = 21
    R_ARM_JUMP_SLOT = 22
    R_ARM_RELATIVE = 23
    R_ARM_GOTOFF32 = 24
    R_ARM_BASE_PREL = 25
    R_ARM_GOT_BREL = 26
    R_ARM_PLT32 = 27
    R_ARM_CALL = 28
    R_ARM_JUMP24 = 29
    R_ARM_THM_JUMP24 = 30
    R_ARM_BASE_ABS = 31
    R_ARM_ALU_PCREL_7_0 = 32
    R_ARM_ALU_PCREL_15_8 = 33
    R_ARM_ALU_PCREL_23_15 = 34
    R_ARM_LDR_SBREL_11_0_NC = 35
    R_ARM_ALU_SBREL_19_12_NC = 36
    R_ARM_ALU_SBREL_27_20_CK = 37
    R_ARM_TARGET1 = 38
    R_ARM_SBREL31 = 39
    R_ARM_V4BX = 40
    R_ARM_TARGET2 = 41
    R_ARM_PREL31 = 42
    R_ARM_MOVW_ABS_NC = 43
    R_ARM_MOVT_ABS = 44
    R_ARM_MOVW_PREL_NC = 45
    R_ARM_MOVT_PREL = 46
    R_ARM_THM_MOVW_ABS_NC = 47
    R_ARM_THM_MOVT_ABS = 48
    R_ARM_THM_MOVW_PREL_NC =  49
    R_ARM_THM_MOVT_PREL = 50
    R_ARM_THM_JUMP19 = 51
    R_ARM_THM_JUMP6 = 52
    R_ARM_THM_ALU_PREL_11_0 = 53
    R_ARM_THM_PC12 = 54
    R_ARM_ABS32_NOI = 55
    R_ARM_REL32_NOI = 56
    R_ARM_ALU_PC_G0_NC = 57
    R_ARM_ALU_PC_G0 = 58
    R_ARM_ALU_PC_G1_NC = 59
    R_ARM_ALU_PC_G1 = 60
    R_ARM_ALU_PC_G2 = 61
    R_ARM_LDR_PC_G1 = 62
    R_ARM_LDR_PC_G2 = 63
    R_ARM_LDRS_PC_G0 = 64
    R_ARM_LDRS_PC_G1 = 65
    R_ARM_LDRS_PC_G2 = 66
    R_ARM_LDC_PC_G0 = 67
    R_ARM_LDC_PC_G1 = 68
    R_ARM_LDC_PC_G2 = 69
    R_ARM_ALU_SB_G0_NC = 70
    R_ARM_ALU_SB_G0 = 71
    R_ARM_ALU_SB_G1_NC = 72
    R_ARM_ALU_SB_G1 = 73
    R_ARM_ALU_SB_G2 = 74
    R_ARM_LDR_SB_G0 = 75
    R_ARM_LDR_SB_G1 = 76
    R_ARM_LDR_SB_G2 = 77
    R_ARM_LDRS_SB_G0 = 78
    R_ARM_LDRS_SB_G1 = 79
    R_ARM_LDRS_SB_G2 = 80
    R_ARM_LDC_SB_G0 = 81
    R_ARM_LDC_SB_G1 = 82
    R_ARM_LDC_SB_G2 = 83
    R_ARM_MOVW_BREL_NC = 84
    R_ARM_MOVT_BREL = 85
    R_ARM_MOVW_BREL = 86
    R_ARM_THM_MOVW_BREL_NC = 87
    R_ARM_THM_MOVT_BREL = 88
    R_ARM_THM_MOVW_BREL = 89
    R_ARM_TLS_GOTDESC = 90
    R_ARM_TLS_CALL = 91
    R_ARM_TLS_DESCSEQ = 92
    R_ARM_THM_TLS_CALL = 93
    R_ARM_PLT32_ABS =  94
    R_ARM_GOT_ABS =  95
    R_ARM_GOT_PREL = 96
    R_ARM_GOT_BREL12 =  97
    R_ARM_GOTOFF12 =  98
    R_ARM_GOTRELAX =  99
    R_ARM_GNU_VTENTRY = 100
    R_ARM_GNU_VTINHERIT = 101
    R_ARM_THM_JUMP11 = 102
    R_ARM_THM_JUMP8 = 103
    R_ARM_TLS_GD32 = 104
    R_ARM_TLS_LDM32 = 105
    R_ARM_TLS_LDO32 = 106
    R_ARM_TLS_IE32 = 107
    R_ARM_TLS_LE32 = 108
    R_ARM_TLS_LDO12 = 109
    R_ARM_TLS_LE12 = 110
    R_ARM_TLS_IE12GP = 111
    R_ARM_PRIVATE_0 = 112
    R_ARM_PRIVATE_1 = 113
    R_ARM_PRIVATE_2 = 114
    R_ARM_PRIVATE_3 = 115
    R_ARM_PRIVATE_4 = 116
    R_ARM_PRIVATE_5 = 117
    R_ARM_PRIVATE_6 = 118
    R_ARM_PRIVATE_7 = 119
    R_ARM_PRIVATE_8 = 120
    R_ARM_PRIVATE_9 = 121
    R_ARM_PRIVATE_10 = 122
    R_ARM_PRIVATE_11 = 123
    R_ARM_PRIVATE_12 = 124
    R_ARM_PRIVATE_13 = 125
    R_ARM_PRIVATE_14 = 126
    R_ARM_PRIVATE_15 = 127
    R_ARM_ME_TOO = 128
    R_ARM_THM_TLS_DESCSEQ16 = 129
    R_ARM_THM_TLS_DESCSEQ32 = 130

###############################################################################
# helper classes
###############################################################################
class StringTable:
    def __init__(self, FP, size):
        self.offset = FP.tell()
        self.size = size
        self.table = FP.read(size)

    def __getitem__(self, offset):
        result = None
        end = offset
        while end < len(self.table) and self.table[end] != 0:
            end += 1
        if end >= len(self.table):
            result = b''
        else:
            result = self.table[offset:end]
        return result.decode('utf-8')

    def replace_string(self, oldstr, newstr):
        offset = 0
        self.table.index(oldstr) # check existence, exception if not found
        self.table = self.table.replace(oldstr, newstr)

    def __str__(self):
        buff = 'offset'.rjust(12) + ' string' + "\n"
        for i in range(self.size):
            if self.table[i] != '\0':
                if i==0 or self.table[i-1] == '\0':
                    buff += ('0x%X' % i).rjust(12) + ' ' + self[i] + "\n"
        return buff

    def toNode(self, node, extra=''):
        n = node.addNode("string table "+extra, self.offset, self.size)
        for i in range(self.size):
            if self.table[i] != '\0':
                if i==0 or self.table[i-1] == '\0':
                    str_ = self[i]
                    n.addNode('0x%X'%i + ' \"' + str_ + "\"", self.offset + i, len(str_)+1)

def isElf(fp):
    elfClass = None
    tmp = fp.tell()
    fp.seek(0)
    if fp.read(4) != b"\x7fELF":
        #print("NO SIGNATURE")
        return False
    elfClass = unpack('B', fp.read(1))[0] # e_ident[EI_CLASS]
    if not (elfClass in [ELFCLASS32, ELFCLASS64]):
        #print("NO elfClass")
        return False
    eiData = unpack('B', fp.read(1))[0] # e_ident[EI_DATA]
    if not eiData in [ELFDATA2LSB, ELFDATA2MSB]:
        #print("NO eiData")
        return False
    eiVersion = unpack('B', fp.read(1))[0]
    if not (eiVersion in [EV_CURRENT]): # e_ident[EI_VERSION]
        #print("NO eiVersion")
        return False
    fp.seek(tmp)
    return (True, elfClass)

def isElf64(fp):
    result = isElf(fp)
    return (result and result[1] == ELFCLASS64)

def isElf32(fp):
    result = isElf(fp)
    return (result and result[1] == ELFCLASS32)

###############################################################################
# main
###############################################################################

if __name__ == '__main__':
    # functions in this file are meant to be "common" functions called from
    # more specialied taggers like elf32 or elf64
    sys.exit(-1)
