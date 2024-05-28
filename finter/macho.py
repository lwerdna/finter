#!/usr/bin/env python3

# references (if you have it):
# sources:
#   /usr/include/mach-o/loader.h and others
#   <llvm>/include/llvm/Support/MachO.h
#   https://awesomeopensource.com/project/aidansteele/osx-abi-macho-file-format-reference
# programs:
#   otool -fahl <file>
#   llvm-readobj --symbols ~/Desktop/fakeintrinsics_bn_64.o
#   llvm-readobj -r ~/Desktop/fakeintrinsics_bn_64.o -r --expand-relocs

import sys
import binascii
from struct import unpack

from enum import Enum

from .helpers import *

# globals
# while parsing load commands segment64, save these areas to parse relocations
reloc_areas = [] # (<offset>, <num_relocs>, <info>)
# while parsing load command symtab
(symtab_offset, symtab_amount, symtab_strtab_offset) = (0, 0, 0)
symtab_strings = []
section_strings = [''] # 1-indexed in macho, given as "<SEGNAME>/<SECNAME> like __TEXT/__stubs"

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
lookup_magic = {MH_MAGIC:'MH_MAGIC', MH_CIGAM:'MH_CIGAM', MH_MAGIC_64:'MH_MAGIC_64',
    MH_CIGAM_64:'MH_CIGAM_64', FAT_MAGIC:'FAT_MAGIC', FAT_CIGAM:'FAT_CIGAM'}

MH_OBJECT = 0x1
MH_EXECUTE = 0x2
MH_FVMLIB = 0x3
MH_CORE = 0x4
MH_PRELOAD = 0x5
MH_DYLIB = 0x6
MH_DYLINKER = 0x7
MH_BUNDLE = 0x8
MH_DYLIB_STUB = 0x9
MH_DSYM = 0xA
MH_KEXT_BUNDLE = 0xB
lookup_filetype = {MH_OBJECT:'MH_OBJECT', MH_EXECUTE:'MH_EXECUTE', MH_FVMLIB:'MH_FVMLIB',
    MH_CORE:'MH_CORE', MH_PRELOAD:'MH_PRELOAD', MH_DYLIB:'MH_DYLIB', MH_DYLINKER:'MH_DYLINKER',
    MH_BUNDLE:'MH_BUNDLE', MH_DYLIB_STUB:'MH_DYLIB_STUB', MH_DSYM:'MH_DSYM',
    MH_KEXT_BUNDLE:'MH_KEXT_BUNDLE'}

# CPU type constants
CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_ANY = 0xFFFFFFFF
CPU_TYPE_VAX = 1
CPU_TYPE_MC680x0 = 6
CPU_TYPE_X86 = 7
CPU_TYPE_I386 = CPU_TYPE_X86
CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_MIPS = 8
CPU_TYPE_MC98000 = 10
CPU_TYPE_HPPA = 11
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64
CPU_TYPE_MC88000 = 13
CPU_TYPE_SPARC = 14
CPU_TYPE_I860 = 15
CPU_TYPE_ALPHA = 16
CPU_TYPE_POWERPC = 18
CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
lookup_cputype = {CPU_TYPE_ANY:'CPU_TYPE_ANY', CPU_TYPE_VAX:'CPU_TYPE_VAX',
    CPU_TYPE_MC680x0:'CPU_TYPE_MC680x0', CPU_TYPE_X86:'CPU_TYPE_X86', CPU_TYPE_I386:'CPU_TYPE_I386',
    CPU_TYPE_X86_64:'CPU_TYPE_X86_64', CPU_TYPE_MIPS:'CPU_TYPE_MIPS', CPU_TYPE_MC98000:'CPU_TYPE_MC98000',
    CPU_TYPE_HPPA:'CPU_TYPE_HPPA', CPU_TYPE_ARM:'CPU_TYPE_ARM', CPU_TYPE_MC88000:'CPU_TYPE_MC88000',
    CPU_TYPE_SPARC:'CPU_TYPE_SPARC', CPU_TYPE_I860:'CPU_TYPE_I860', CPU_TYPE_ALPHA:'CPU_TYPE_ALPHA',
    CPU_TYPE_POWERPC:'CPU_TYPE_POWERPC', CPU_TYPE_POWERPC64:'CPU_TYPE_POWERPC64'
}

# CPU subtype constants
CPU_SUBTYPE_MASK = 0xFF000000
CPU_SUBTYPE_LIB64 = 0x80000000
CPU_SUBTYPE_MULTIPLE = 0xFFFFFFFF
CPU_SUBTYPE_I386_ALL = 3
CPU_SUBTYPE_386 = 3
CPU_SUBTYPE_486 = 4
CPU_SUBTYPE_486SX = 0x84
CPU_SUBTYPE_586 = 5
CPU_SUBTYPE_PENT = CPU_SUBTYPE_586
CPU_SUBTYPE_PENTPRO = 0x16
CPU_SUBTYPE_PENTII_M3 = 0x36
CPU_SUBTYPE_PENTII_M5 = 0x56
CPU_SUBTYPE_CELERON = 0x67
CPU_SUBTYPE_CELERON_MOBILE = 0x77
CPU_SUBTYPE_PENTIUM_3 = 0x08
CPU_SUBTYPE_PENTIUM_3_M = 0x18
CPU_SUBTYPE_PENTIUM_3_XEON = 0x28
CPU_SUBTYPE_PENTIUM_M = 0x09
CPU_SUBTYPE_PENTIUM_4 = 0x0a
CPU_SUBTYPE_PENTIUM_4_M = 0x1a
CPU_SUBTYPE_ITANIUM = 0x0b
CPU_SUBTYPE_ITANIUM_2 = 0x1b
CPU_SUBTYPE_XEON = 0x0c
CPU_SUBTYPE_XEON_MP = 0x1c
lookup_cpusubtype_capabilities = { 0:'None', CPU_SUBTYPE_LIB64:'CPU_SUBTYPE_LIB64' }
lookup_cpusubtype = { CPU_SUBTYPE_I386_ALL:'CPU_SUBTYPE_I386_ALL', CPU_SUBTYPE_386:'CPU_SUBTYPE_386', CPU_SUBTYPE_486:'CPU_SUBTYPE_486',
    CPU_SUBTYPE_486SX:'CPU_SUBTYPE_486SX', CPU_SUBTYPE_586:'CPU_SUBTYPE_586', CPU_SUBTYPE_PENT:'CPU_SUBTYPE_PENT',
    CPU_SUBTYPE_PENTPRO:'CPU_SUBTYPE_PENTPRO', CPU_SUBTYPE_PENTII_M3:'CPU_SUBTYPE_PENTII_M3', CPU_SUBTYPE_PENTII_M5:'CPU_SUBTYPE_PENTII_M5',
    CPU_SUBTYPE_CELERON:'CPU_SUBTYPE_CELERON', CPU_SUBTYPE_CELERON_MOBILE:'CPU_SUBTYPE_CELERON_MOBILE', CPU_SUBTYPE_PENTIUM_3:'CPU_SUBTYPE_PENTIUM_3',
    CPU_SUBTYPE_PENTIUM_3_M:'CPU_SUBTYPE_PENTIUM_3_M', CPU_SUBTYPE_PENTIUM_3_XEON:'CPU_SUBTYPE_PENTIUM_3_XEON', CPU_SUBTYPE_PENTIUM_M:'CPU_SUBTYPE_PENTIUM_M',
    CPU_SUBTYPE_PENTIUM_4:'CPU_SUBTYPE_PENTIUM_4', CPU_SUBTYPE_PENTIUM_4_M:'CPU_SUBTYPE_PENTIUM_4_M', CPU_SUBTYPE_ITANIUM:'CPU_SUBTYPE_ITANIUM',
    CPU_SUBTYPE_ITANIUM_2:'CPU_SUBTYPE_ITANIUM_2', CPU_SUBTYPE_XEON:'CPU_SUBTYPE_XEON', CPU_SUBTYPE_XEON_MP:'CPU_SUBTYPE_XEON_MP',
}

MH_NOUNDEFS = 0x00000001
MH_INCRLINK = 0x00000002
MH_DYLDLINK = 0x00000004
MH_BINDATLOAD = 0x00000008
MH_PREBOUND = 0x00000010
MH_SPLIT_SEGS = 0x00000020
MH_LAZY_INIT = 0x00000040
MH_TWOLEVEL = 0x00000080
MH_FORCE_FLAT = 0x00000100
MH_NOMULTIDEFS = 0x00000200
MH_NOFIXPREBINDING = 0x00000400
MH_PREBINDABLE = 0x00000800
MH_ALLMODSBOUND = 0x00001000
MH_SUBSECTIONS_VIA_SYMBOLS = 0x00002000
MH_CANONICAL = 0x00004000
MH_WEAK_DEFINES = 0x00008000
MH_BINDS_TO_WEAK = 0x00010000
MH_ALLOW_STACK_EXECUTION = 0x00020000
MH_ROOT_SAFE = 0x00040000
MH_SETUID_SAFE = 0x00080000
MH_NO_REEXPORTED_DYLIBS = 0x00100000
MH_PIE = 0x00200000
MH_DEAD_STRIPPABLE_DYLIB = 0x00400000
MH_HAS_TLV_DESCRIPTORS = 0x00800000
MH_NO_HEAP_EXECUTION = 0x01000000
MH_APP_EXTENSION_SAFE = 0x02000000

# masks for section/section64 .flags property
SCN_TYPE_MASK           = 0x000000ff
SCN_ATTRIBUTES_USR_MASK = 0xff000000
SCN_ATTRIBUTES_SYS_MASK = 0x00ffff00
SCN_ATTRIBUTES_MASK     = (SCN_ATTRIBUTES_USR_MASK | SCN_ATTRIBUTES_SYS_MASK)

# values for section .flags & SECTION_TYPE
class SECTION_TYPE(Enum):
    S_REGULAR = 0x00
    S_ZEROFILL = 0x01
    S_CSTRING_LITERALS = 0x02
    S_4BYTE_LITERALS = 0x03
    S_8BYTE_LITERALS = 0x04
    S_LITERAL_POINTERS = 0x05
    S_NON_LAZY_SYMBOL_POINTERS = 0x06
    S_LAZY_SYMBOL_POINTERS = 0x07
    S_SYMBOL_STUBS = 0x08
    S_MOD_INIT_FUNC_POINTERS = 0x09
    S_MOD_TERM_FUNC_POINTERS = 0x0a
    S_COALESCED = 0x0b
    S_GB_ZEROFILL = 0x0c
    S_INTERPOSING = 0x0d
    S_16BYTE_LITERALS = 0x0e
    S_DTRACE_DOF = 0x0f
    S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10
    S_THREAD_LOCAL_REGULAR = 0x11
    S_THREAD_LOCAL_ZEROFILL = 0x12
    S_THREAD_LOCAL_VARIABLES = 0x13
    S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14
    S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15

def section_type_str(x):
    try:
        return SECTION_TYPE(x & SCN_TYPE_MASK).name
    except ValueError:
        return 'UNKNOWN'

# values for section .flags & SECTION_ATTRIBUTES_USR
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_NO_TOC = 0x40000000
S_ATTR_STRIP_STATIC_SYMS = 0x20000000
S_ATTR_NO_DEAD_STRIP = 0x10000000
S_ATTR_LIVE_SUPPORT = 0x08000000
S_ATTR_SELF_MODIFYING_CODE = 0x04000000
S_ATTR_DEBUG = 0x02000000

# values for section .flags & SECTION_ATTRIBUTES_SYS
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
S_ATTR_EXT_RELOC = 0x00000200
S_ATTR_LOC_RELOC = 0x00000100

def section_attrs_str(x):
    result = []
    usr = x & SCN_ATTRIBUTES_USR_MASK
    if usr & S_ATTR_PURE_INSTRUCTIONS: result.append('PURE_INSTRUCTIONS')
    if usr & S_ATTR_NO_TOC: result.append('S_ATTR_NO_TOC')
    if usr & S_ATTR_STRIP_STATIC_SYMS: result.append('S_ATTR_STRIP_STATIC_SYMS')
    if usr & S_ATTR_NO_DEAD_STRIP: result.append('S_ATTR_NO_DEAD_STRIP')
    if usr & S_ATTR_LIVE_SUPPORT: result.append('S_ATTR_LIVE_SUPPORT')
    if usr & S_ATTR_SELF_MODIFYING_CODE: result.append('S_ATTR_SELF_MODIFYING_CODE')
    if usr & S_ATTR_DEBUG: result.append('S_ATTR_DEBUG')

    sys = x & SCN_ATTRIBUTES_SYS_MASK
    if sys & S_ATTR_SOME_INSTRUCTIONS: result.append('S_ATTR_SOME_INSTRUCTIONS')
    if sys & S_ATTR_EXT_RELOC: result.append('S_ATTR_EXT_RELOC')
    if sys & S_ATTR_LOC_RELOC: result.append('S_ATTR_LOC_RELOC')

    return '|'.join(result)

# Constants for the cmd field of all load commands, the type
class LOAD_COMMAND_TYPE(Enum):
    LC_REQ_DYLD = 0x80000000
    LC_SEGMENT = 0x1
    LC_SYMTAB = 0x2
    LC_SYMSEG = 0x3
    LC_THREAD = 0x4
    LC_UNIXTHREAD = 0x5
    LC_LOADFVMLIB = 0x6
    LC_IDFVMLIB = 0x7
    LC_IDENT = 0x8
    LC_FVMFILE = 0x9
    LC_PREPAGE = 0xa
    LC_DYSYMTAB = 0xb
    LC_LOAD_DYLIB = 0xc
    LC_ID_DYLIB = 0xd
    LC_LOAD_DYLINKER = 0xe
    LC_ID_DYLINKER = 0xf
    LC_PREBOUND_DYLIB = 0x10
    LC_ROUTINES = 0x11
    LC_SUB_FRAMEWORK = 0x12
    LC_SUB_UMBRELLA = 0x13
    LC_SUB_CLIENT = 0x14
    LC_SUB_LIBRARY  = 0x15
    LC_TWOLEVEL_HINTS = 0x16
    LC_PREBIND_CKSUM  = 0x17
    LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD)
    LC_SEGMENT_64 = 0x19
    LC_ROUTINES_64 = 0x1a
    LC_UUID = 0x1b
    LC_RPATH = (0x1c | LC_REQ_DYLD)
    LC_CODE_SIGNATURE = 0x1d
    LC_SEGMENT_SPLIT_INFO = 0x1e
    LC_REEXPORT_DYLIB = (0x1f | LC_REQ_DYLD)
    LC_LAZY_LOAD_DYLIB = 0x20
    LC_ENCRYPTION_INFO = 0x21
    LC_DYLD_INFO  = 0x22
    LC_DYLD_INFO_ONLY = (0x22|LC_REQ_DYLD)
    LC_LOAD_UPWARD_DYLIB = (0x23 | LC_REQ_DYLD)
    LC_VERSION_MIN_MACOSX = 0x24
    LC_VERSION_MIN_IPHONEOS = 0x25
    LC_FUNCTION_STARTS = 0x26
    LC_DYLD_ENVIRONMENT = 0x27
    LC_MAIN = (0x28|LC_REQ_DYLD)
    LC_DATA_IN_CODE = 0x29
    LC_SOURCE_VERSION = 0x2A
    LC_DYLIB_CODE_SIGN_DRS = 0x2B
    LC_ENCRYPTION_INFO_64 = 0x2C
    LC_LINKER_OPTION = 0x2D
    LC_LINKER_OPTIMIZATION_HINT = 0x2E
    LC_VERSION_MIN_TVOS = 0x2f
    LC_VERSION_MIN_WATCHOS = 0x30
    LC_NOTE = 0x31
    LC_BUILD_VERSION = 0x32

# .initprop property of segment command
VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4
def vm_prot_str(x):
    result = []
    if x & VM_PROT_READ: result.append('R')
    if x & VM_PROT_WRITE: result.append('W')
    if x & VM_PROT_EXECUTE: result.append('X')
    return '|'.join(result)

#------------------------------------------------------------------------------
# symbol table types, helpers
#------------------------------------------------------------------------------

def string_abduct(fp, offset):
    anchor = fp.tell()
    fp.seek(offset)
    tmp = string_null(fp)
    fp.seek(anchor)
    return tmp

# struct nlist[_64] {
#   uint32_t n_strx;
#   uint8_t n_type;
#   uint8_t n_sect;
#   int16_t n_desc;
#   uint[32|64]_t n_value;
# };
def tag_nlist(fp, cputype, stroff):
    # whole struct
    if cputype & CPU_ARCH_ABI64:
        tag(fp, 16, 'nlist_64', 1)
    else:
        tag(fp, 12, 'nlist', 1)

    # .n_strx
    n_strx = uint32(fp, 1)
    sym_name = string_abduct(fp, stroff + n_strx) if n_strx else ''
    tag(fp, 4, 'n_strx: 0x%x "%s"' % (n_strx, sym_name))

    # .n_type has 4 subfields
    n_type = uint8(fp, 1)
    n_stab = (n_type & 0xe0) >> 5
    n_pext = (n_type & 0x10) >> 4
    n_type = (n_type & 0xe) >> 1
    n_ext = n_type & 1
    descr = []
    descr.append('n_type')
    descr.append('  N_STAB: %s' % bin(n_stab))
    descr.append('  N_PEXT: %s' % bin(n_pext))
    if n_type == 0:
        descr.append('  N_TYPE: N_UNDF (0)')
    elif n_type == 2:
        descr.append('  N_TYPE: N_ABS (2)')
    elif n_type == 0xe:
        descr.append('  N_TYPE: N_SECT (0xe)')
    elif n_type == 0xc:
        descr.append('  N_TYPE: N_PBUD (0xc)')
    elif n_type == 0xa:
        descr.append('  N_TYPE: N_INDR (0xa)')
    else:
        descr.append('  N_TYPE: 0x%x' % n_type)
    descr.append('  N_EXT: %s' % bin(n_ext))
    tag(fp, 1, '\\n'.join(descr))

    # .n_sect
    tagUint8(fp, 'n_sect')

    # .n_desc
    tagUint16(fp, 'n_desc')

    # .n_value
    if cputype & CPU_ARCH_ABI64:
        tagUint64(fp, 'n_value')
    else:
        tagUint32(fp, 'n_value')

    return sym_name

#------------------------------------------------------------------------------
# relocation types, helpers
#------------------------------------------------------------------------------

class RELOC_TYPE_GENERIC(Enum):
    # Constant values for the r_type field in an
    # llvm::MachO::relocation_info or llvm::MachO::scattered_relocation_info
    # structure.
    GENERIC_RELOC_INVALID = 0xff
    GENERIC_RELOC_VANILLA = 0
    GENERIC_RELOC_PAIR = 1
    GENERIC_RELOC_SECTDIFF = 2
    GENERIC_RELOC_PB_LA_PTR = 3
    GENERIC_RELOC_LOCAL_SECTDIFF = 4
    GENERIC_RELOC_TLV = 5

class RELOC_TYPE_PPC(Enum):
    # Constant values for the r_type field in a PowerPC architecture
    # llvm::MachO::relocation_info or llvm::MachO::scattered_relocation_info
    # structure.
    PPC_RELOC_VANILLA = RELOC_TYPE_GENERIC.GENERIC_RELOC_VANILLA
    PPC_RELOC_PAIR = RELOC_TYPE_GENERIC.GENERIC_RELOC_PAIR
    PPC_RELOC_BR14 = 2
    PPC_RELOC_BR24 = 3
    PPC_RELOC_HI16 = 4
    PPC_RELOC_LO16 = 5
    PPC_RELOC_HA16 = 6
    PPC_RELOC_LO14 = 7
    PPC_RELOC_SECTDIFF = 8
    PPC_RELOC_PB_LA_PTR = 9
    PPC_RELOC_HI16_SECTDIFF = 10
    PPC_RELOC_LO16_SECTDIFF = 11
    PPC_RELOC_HA16_SECTDIFF = 12
    PPC_RELOC_JBSR = 13
    PPC_RELOC_LO14_SECTDIFF = 14
    PPC_RELOC_LOCAL_SECTDIFF = 15

class RELOC_TYPE_ARM(Enum):
    # Constant values for the r_type field in an ARM architecture
    # llvm::MachO::relocation_info or llvm::MachO::scattered_relocation_info
    # structure.
    ARM_RELOC_VANILLA = RELOC_TYPE_GENERIC.GENERIC_RELOC_VANILLA
    ARM_RELOC_PAIR = RELOC_TYPE_GENERIC.GENERIC_RELOC_PAIR
    ARM_RELOC_SECTDIFF = RELOC_TYPE_GENERIC.GENERIC_RELOC_SECTDIFF
    ARM_RELOC_LOCAL_SECTDIFF = 3
    ARM_RELOC_PB_LA_PTR = 4
    ARM_RELOC_BR24 = 5
    ARM_THUMB_RELOC_BR22 = 6
    ARM_THUMB_32BIT_BRANCH = 7
    ARM_RELOC_HALF = 8
    ARM_RELOC_HALF_SECTDIFF = 9

class RELOC_TYPE_ARM64(Enum):
    # Constant values for the r_type field in an ARM64 architecture
    # llvm::MachO::relocation_info or llvm::MachO::scattered_relocation_info
    # structure.

    # For pointers.
    ARM64_RELOC_UNSIGNED = 0
    # Must be followed by an ARM64_RELOC_UNSIGNED
    ARM64_RELOC_SUBTRACTOR = 1
    # A B/BL instruction with 26-bit displacement.
    ARM64_RELOC_BRANCH26 = 2
    # PC-rel distance to page of target.
    ARM64_RELOC_PAGE21 = 3
    # Offset within page, scaled by r_length.
    ARM64_RELOC_PAGEOFF12 = 4
    # PC-rel distance to page of GOT slot.
    ARM64_RELOC_GOT_LOAD_PAGE21 = 5
    # Offset within page of GOT slot, scaled by r_length.
    ARM64_RELOC_GOT_LOAD_PAGEOFF12 = 6
    # For pointers to GOT slots.
    ARM64_RELOC_POINTER_TO_GOT = 7
    # PC-rel distance to page of TLVP slot.
    ARM64_RELOC_TLVP_LOAD_PAGE21 = 8
    # Offset within page of TLVP slot, scaled by r_length.
    ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9
    # Must be followed by ARM64_RELOC_PAGE21 or ARM64_RELOC_PAGEOFF12.
    ARM64_RELOC_ADDEND = 10

class RELOC_TYPE_X86_64(Enum):
    # Constant values for the r_type field in an x86_64 architecture
    # llvm::MachO::relocation_info or llvm::MachO::scattered_relocation_info
    # structure
    X86_64_RELOC_UNSIGNED = 0
    X86_64_RELOC_SIGNED = 1
    X86_64_RELOC_BRANCH = 2
    X86_64_RELOC_GOT_LOAD = 3
    X86_64_RELOC_GOT = 4
    X86_64_RELOC_SUBTRACTOR = 5
    X86_64_RELOC_SIGNED_1 = 6
    X86_64_RELOC_SIGNED_2 = 7
    X86_64_RELOC_SIGNED_4 = 8
    X86_64_RELOC_TLV = 9

R_ABS = 0
R_SCATTERED = 0x80000000

#struct relocation_info {
#    int32_t r_address; // in MH_OBJECT, this is offset from start of section to address needing adjusting
#                      // in executables loaded by dynamic loader (MH_EXECUTE, MH_DYLIB)? this is offset from

#                      // if b31 (R_SCATTERED) set, this is scattered_relocation_info, not relocation_info
#    uint32_t r_symbolnum:24,
#    uint32_t r_pcrel:1;
#    uint32_t r_length:2; // {1,2,4,8} bytes
#    uint32_t r_extern:1;
#    uint32_t r_type:4;
#};

def tag_relocation_info(fp, cputype, sym_table_names, comment=''):
    base = fp.tell()

    # peek at r_address, determine entire structure size
    r_address = uint32(fp, 1)
    if r_address & R_SCATTERED:
        tag(fp, 4+4, 'struct scattered_relocation_info%s' % comment, 1)
    else:
        tag(fp, 4+4, 'struct relocation_info%s' % comment, 1)
    fp.seek(base)
    tag(fp, 4, 'r_address: 0x%X' % r_address)
    # r_address:
    # in MH_OBJECT files, this is an offset from the start of the section to the item containing the address requiring relocation.
    # in images used by the dynamic linker, this is an offset from the virtual memory address of the data of the first segment_command that appears in the file (not necessarily the one with the lowest address).
    # in images with the MH_SPLIT_SEGS flag set, this is an offset from the virtual memory address of data of the first read/write segment_command.

    tmp = uint32(fp, 1)
    r_symbolnum = tmp & 0xFFFFFF
    r_pcrel = (tmp >> 24) & 1
    r_length = (tmp >> 25) & 2
    r_extern = (tmp >> 27) & 1
    r_type = (tmp >> 28) & 0xF

    r_type_str = ''
    if cputype == CPU_TYPE_ARM64:
        r_type_str = RELOC_TYPE_ARM64(r_type).name
    elif cputype == CPU_TYPE_X86_64:
        r_type_str = RELOC_TYPE_X86_64(r_type).name

    descr = []
    if r_extern == 1:
        descr.append('r_symbolnum: 0x%X (symbol table index)' % r_symbolnum)
        if r_symbolnum < len(symtab_strings):
            descr[-1] = 'r_symbolnum: 0x%X "%s"' % (r_symbolnum, symtab_strings[r_symbolnum])
    else:
        descr.append('r_symbolnum: 0x%X (section number [1,255])' % r_symbolnum)
        if r_symbolnum < len(section_strings):
            descr[-1] = 'r_symbolnum: 0x%X section "%s"' % (r_symbolnum, section_strings[r_symbolnum])
    descr.append('r_pcrel: %d' % r_pcrel)
    descr.append('r_length: %s bytes (%d)' % (2**r_length, r_length))
    descr.append('r_extern: %d' % r_extern)
    descr.append('r_type: %s (%d)' % (r_type_str, r_extern))

    tag(fp, 4, '\\n'.join(descr))
    return 8

#------------------------------------------------------------------------------
# "main"
#------------------------------------------------------------------------------

(is32,is64) = (False, False)

def analyze(fp):
    # sample the header for sane values
    magic = uint32(fp, True)

    if magic in [MH_MAGIC_64, MH_MAGIC]:
        setLittleEndian()
    elif magic in [MH_CIGAM_64, MH_CIGAM]:
        setBigEndian()
    else:
        return

    if magic in [MH_MAGIC_64, MH_CIGAM_64]:
        (is32,is64) = (False, True)
    else:
        (is32,is64) = (True, False)

    cputype = uint32(fp)
    fp.seek(0)

    # actually read the header now
    if is64:
        tag(fp, 4+4+4+4+4+4+4+4, "mach_header_64", 1)
    else:
        tag(fp, 4+4+4+4+4+4+4, "mach_header", 1)
    magic = uint32(fp, True)
    tag(fp, 4, "magic=%08X (%s)" % (magic, lookup_magic[magic]))
    cputype = uint32(fp, True)
    tag(fp, 4, "cputype=%08X (%s)" % (cputype, lookup_cputype.get(cputype)))
    a = uint32(fp, True)
    subtype = a & 0xFF
    capabilities = a & CPU_SUBTYPE_MASK
    b = '%d (unknown)' % subtype
    if subtype in lookup_cpusubtype:
        b = lookup_cpusubtype[subtype]
    if capabilities:
        b = '%s|%s' % (lookup_cpusubtype_capabilities[capabilities], b)
    tag(fp, 4, "cpusubtype=%08X (%s)" % (a, b))
    filetype = uint32(fp, True)
    tag(fp, 4, "filetype=%08X (%s)" % (filetype, lookup_filetype[filetype]))
    # etc....
    ncmds = tagUint32(fp, "ncmds")
    tagUint32(fp, "sizeofcmds") # some of all cmdSize to follow
    tagUint32(fp, "flags")
    if is64:
        tagUint32(fp, "reserved")

    # parse commands
    for i in range(ncmds):
        oCmd = fp.tell()
        cmd = tagUint32(fp, "cmd")
        cmdSize = tagUint32(fp, "cmdsize") # includes cmd,cmdsize

        cmd = LOAD_COMMAND_TYPE(cmd)

        if cmd == LOAD_COMMAND_TYPE.LC_SEGMENT_64:
            segname = tagString(fp, 16, "segname")
            tagUint64(fp, "vmaddr")
            tagUint64(fp, "vmsize")
            tagUint64(fp, "fileoff")
            tagUint64(fp, "filesize")
            tagUint32(fp, "maxprot")
            initprot = uint32(fp, "initprot")
            tag(fp, 4, 'initprot=0x%X %s' % (initprot, vm_prot_str(initprot)))

            nsects = tagUint32(fp, "nsects")
            flags = tagUint32(fp, "flags")

            for j in range(nsects):
                oScn = fp.tell()
                sectname = tagString(fp, 16, "sectname")
                segname = tagString(fp, 16, "segname")
                tagUint64(fp, "addr")
                size = tagUint64(fp, "size")
                offset = tagUint32(fp, "offset")
                tagUint32(fp, "align")
                reloff = tagUint32(fp, "reloff")
                nreloc = tagUint32(fp, "nreloc")
                flags = uint32(fp, 1)
                tag(fp, 4, "flags=0x%X\\n  type: %s\\n  attrs: %s" % \
                    (flags, section_type_str(flags), section_attrs_str(flags)))
                tagUint32(fp, "reserved1")
                tagUint32(fp, "reserved2")
                tagUint32(fp, "reserved3")
                print('[0x%X,0x%X) section_64 \"%s\" %d/%d' % \
                    (oScn, fp.tell(), sectname, j+1, nsects))

                # tag section body
                print('[0x%X,0x%X) section %s/%s contents' % \
                    (offset, offset+size, segname, sectname))

                # save section name
                section_strings.append('%s/%s' % (segname, sectname))

                # save reloc reference for later parsing
                reloc_areas.append((reloff, nreloc, '(section %s)' % sectname))

            print('[0x%X,0x%X) segment_command_64 \"%s\"' % \
                (oCmd, fp.tell(), segname))

        elif cmd == LOAD_COMMAND_TYPE.LC_LOAD_DYLIB:
            # parse the dylib
            #tag(fp, 16, "dylib", 1)
            lc_str = tagUint32(fp, "lc_str")
            tagUint32(fp, "timestamp")
            tagUint32(fp, "current_version")
            tagUint32(fp, "compatibility_version")

            # parse the string after the dylib (but before the end of the command)
            fp.seek(oCmd + lc_str)
            path = string(fp, cmdSize - lc_str)

            print('[0x%X,0x%X) path "%s"' % \
                (oCmd+lc_str, oCmd+cmdSize, path))

            print('[0x%X,0x%X) dylib_command \"%s\"' % \
                (oCmd, oCmd+cmdSize, path))

        elif cmd == LOAD_COMMAND_TYPE.LC_LOAD_DYLINKER:
            lc_str = tagUint32(fp, "lc_str")
            # parse the string after the dylinker_command (but before the end of the command)
            fp.seek(oCmd + lc_str)
            path = string(fp, cmdSize - lc_str)

            print('[0x%X,0x%X) dylinker_command \"%s\"' % \
                (oCmd, oCmd+cmdSize, path))

        elif (cmd == LOAD_COMMAND_TYPE.LC_DYLD_INFO) or (cmd == LOAD_COMMAND_TYPE.LC_DYLD_INFO_ONLY):
            tagUint32(fp, "rebase_off")
            tagUint32(fp, "rebase_size")
            tagUint32(fp, "bind_off")
            tagUint32(fp, "bind_size")
            tagUint32(fp, "weak_bind_off")
            tagUint32(fp, "weak_bind_size")
            tagUint32(fp, "lazy_bind_off")
            tagUint32(fp, "lazy_bind_size")
            tagUint32(fp, "export_off")
            tagUint32(fp, "export_size")
            print('[0x%X,0x%X) raw dyld_info_command' % \
                (oCmd, fp.tell()))

        elif cmd == LOAD_COMMAND_TYPE.LC_SYMTAB:
            symoff = tagUint32(fp, "symoff")
            nsyms = tagUint32(fp, "nsyms")
            stroff = tagUint32(fp, "stroff")
            tagUint32(fp, "strsize")
            print('[0x%X,0x%X) raw symtab_command' % \
                (oCmd, fp.tell()))

            (symtab_offset, symtab_amount, symtab_strtab_offset) = (symoff, nsyms, stroff)

        elif cmd == LOAD_COMMAND_TYPE.LC_UUID:
            uuid = tag(fp, 16, "uuid")
            print('[0x%X,0x%X) uuid_command "%s"' % \
                (oCmd, oCmd+cmdSize, binascii.hexlify(uuid)))

        elif cmd == LOAD_COMMAND_TYPE.LC_VERSION_MIN_MACOSX or cmd == LOAD_COMMAND_TYPE.LC_VERSION_MIN_IPHONEOS:
            version = tagUint32(fp, "version")
            x = (version & 0xFFFF0000) >> 16
            y = (version & 0x0000FF00) >> 8
            z = (version & 0x000000FF) >> 0
            strVersion = '%d.%d.%d' % (x,y,z)
            sdk = tagUint32(fp, "sdk")
            x = (sdk & 0xFFFF0000) >> 16
            y = (sdk & 0x0000FF00) >> 8
            z = (sdk & 0x000000FF) >> 0
            strSdk = '%d.%d.%d' % (x,y,z)
            print('[0x%X,0x%X) version_min_command ver=%s sdk=%s' % \
                (oCmd, oCmd+cmdSize, strVersion, strSdk))

        elif cmd == LOAD_COMMAND_TYPE.LC_SOURCE_VERSION:
            version = tagUint64(fp, "version")
            a = (0xFFFFFF0000000000 & version) >> 40
            b = (0x000000FFC0000000 & version) >> 30
            c = (0x000000003FF00000 & version) >> 20
            d = (0x00000000000FFC00 & version) >> 10
            e = (0x00000000000003FF & version) >> 0
            print('[0x%X,0x%X) source_version_command %s.%s.%s.%s.%s' % \
                (oCmd, oCmd+cmdSize, str(a), str(b), str(c), str(d), str(e)))

        elif cmd == LOAD_COMMAND_TYPE.LC_MAIN:
            entrypoint = tagUint32(fp, "entryoff")
            tagUint32(fp, "stacksize")
            print('[0x%X,0x%X) entry_point_command (main @0x%08X)' % \
                (oCmd, oCmd+cmdSize, entrypoint))
            if fp.tell() < (oCmd+cmdSize):
                tag(fp, oCmd+cmdSize-fp.tell(), "padding")

        elif cmd in [LOAD_COMMAND_TYPE.LC_FUNCTION_STARTS, LOAD_COMMAND_TYPE.LC_DATA_IN_CODE]:
            offs = tagUint32(fp, 'data offset')
            length = tagUint32(fp, 'data length')
            print('[0x%X,0x%X) raw %s' % (oCmd, oCmd+cmdSize, cmd.name))

            if length:
                fp.seek(offs)
                tag(fp, length, '%s data'%cmd.name, True)
                idx = 0
                while fp.tell() < offs+length:
                    comment = 'entry%d' % idx
                    if not idx:
                        comment += ' (file offset of __text)'
                    tagUleb128(fp, comment)
                    idx += 1

            fp.seek(oCmd+cmdSize)

        elif cmd == LOAD_COMMAND_TYPE.LC_DYSYMTAB:
            tagUint32(fp, "ilocalsym")
            tagUint32(fp, "nlocalsym")
            tagUint32(fp, "iextdefsym")
            tagUint32(fp, "nextdefsym")
            tagUint32(fp, "iundefsym")
            tagUint32(fp, "nundefsym")
            tagUint32(fp, "tocoff")
            tagUint32(fp, "ntoc")
            tagUint32(fp, "modtaboff")
            tagUint32(fp, "nmodtab")
            tagUint32(fp, "extrefsymoff")
            tagUint32(fp, "nextrefsyms")
            tagUint32(fp, "indirectsymoff")
            tagUint32(fp, "nindirectsyms")
            tagUint32(fp, "extreloff")
            tagUint32(fp, "nextrel")
            locreloff = tagUint32(fp, "locreloff")
            nlocrel = tagUint32(fp, "nlocrel")
            print('[0x%X,0x%X) raw dysymtab_command' % \
                (oCmd, fp.tell()))

            if locreloff and nlocrel:
                reloc_areas.append((locreloff, nlocrel, '(dysymtab)'))
        else:
            print('[0x%X,0x%X) command %s' % \
                (oCmd, oCmd+cmdSize, LOAD_COMMAND_TYPE(cmd).name))
            tag(fp, cmdSize-8, 'data')

    # post-command parsing

    # parse symbol table
    if symtab_offset:
        fp.seek(symtab_offset)
        for i in range(symtab_amount):
            sym_name = tag_nlist(fp, cputype, symtab_strtab_offset)
            symtab_strings.append(sym_name)
        print('[0x%X,0x%X) raw symbol table contents' % (symtab_offset, fp.tell()))

    # parse relocation areas referenced by sections
    for (reloff, nreloc, info) in reloc_areas:
        anchor = fp.tell()
        fp.seek(reloff)
        for i in range(nreloc):
            tag_relocation_info(fp, cputype, [], info)
        fp.seek(anchor)

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
