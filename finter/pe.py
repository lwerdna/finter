#!/usr/bin/env python

# PE64 vs. PE32
# 1) different id in image_nt_headers.image_file_header.Machine
# 2) image_optional_header at 0xE0 (224 bytes) is replaced by
#   image_optional_header64 at 0xF0 (240 bytes) with:
#   2.1) BaseOfData is GONE, its bytes get absorbed into ImageBase, growing it
#        from 4 bytes to 8 bytes
#   2.2) all these fields grow from 4 to 8 bytes:
#   - SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit
#     all increase from 4 bytes to 8 bytes
#
# this should result in an image_optional_header that is 0xF0 bytes

import os
import sys

from .helpers import *
from struct import pack, unpack

from enum import Enum, auto, unique

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_SIZEOF_IMAGE_DATA_DIRECTORY = 8
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_SIZEOF_SECTION_HEADER = 40
IMAGE_SIZEOF_FILE_HEADER = 20
IMAGE_SIZEOF_SECTION_HEADER = 40
IMAGE_SIZEOF_SYMBOL = 18
IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR = 60

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107

class IMAGE_FILE_MACHINE(Enum):
    I386 = 0x014c
    IA64 = 0x0200
    AMD64 = 0x8664
    ARM64 = 0xAA64

class IMAGE_DIRECTORY_ENTRY(Enum):
    EXPORT = 0
    IMPORT = 1
    RESOURCE = 2
    EXCEPTION = 3
    SECURITY = 4
    BASERELOC = 5
    DEBUG = 6
    ARCHITECTURE = 7
    GLOBALPTR = 8
    TLS = 9
    LOAD_CONFIG = 10
    BOUND_IMPORT = 11
    IAT = 12
    DELAY_IMPORT = 13
    COM_DESCRIPTOR = 14
    UNKNOWN = 15

class COMIMAGE_FLAGS(Enum):
    ILONLY = 1
    _32BITREQUIRED = 2
    IL_LIBRARY = 4
    STRONGNAMESIGNED = 8
    NATIVE_ENTRYPOINT = 16
    TRACKDEBUGDATA = 0x10000

def idFile(fp):
    fpos = fp.tell()

    # get file size
    fp.seek(0, os.SEEK_END)
    fileSize = fp.tell()
    #print "fileSize: 0x%X (%d)" % (fileSize, fileSize)

    # file large enough to hold IMAGE_DOS_HEADER ?
    if fileSize < 0x40:
        #print "file too small to hold IMAGE_DOS_HEADER"
        fp.seek(fpos)
        return False

    # is IMAGE_DOS_HEADER.e_magic == "MZ" ?
    fp.seek(0)
    if fp.read(2) != b'MZ':
        #print "missing MZ identifier"
        fp.seek(fpos)
        return False

    # get IMAGE_DOS_HEADER.e_lfanew
    fp.seek(0x3C)
    e_lfanew = unpack('<I', fp.read(4))[0]

    # is file large enough to hold IMAGE_NT_HEADERS ?
    if fileSize < (e_lfanew + 0x108):
        #print "file too small to hold IMAGE_NT_HEADERS"
        fp.seek(fpos)
        return False

    # does IMAGE_NT_HEADERS.signature == "PE" ?
    fp.seek(e_lfanew)
    if fp.read(4) != b'PE\x00\x00':
        #print "missing PE identifier"
        fp.seek(fpos)
        return False

    #
    result = "unknown"
    (machine,) = unpack('<H', fp.read(2))
    if machine in [IMAGE_FILE_MACHINE.AMD64.value, IMAGE_FILE_MACHINE.ARM64.value]:
        result = "pe64"
    if machine in [IMAGE_FILE_MACHINE.I386.value]:
        result = "pe32"
    fp.seek(fpos)
    return result

def relocTypeToStr(t, machine=''):
    lookup = ["ABSOLUTE", "HIGH", "LOW", "HIGHLOW", "HIGHADJ"] # index [0,4]
    lookup.append({'':'UNKNOWN', 'mips':'MIPS_JMPADDR', # index 5
        'arm':'ARM_MOV32', 'thumb':'ARM_MOV32',
        'risc-v':'RISCV_HIGH20'}[machine])
    lookup.append('RESERVED') # index 6
    lookup.append({'':'UNKNOWN', 'arm':'ARM_MOV32', # index 7
        'thumb':'ARM_MOV32', 'risc-v':'RISCV_HIGH20'}[machine])
    lookup += ['RISCV_LOW12S'] # index 8
    lookup += ['JMPADDR16'] # index 9
    lookup += ['DIR64'] # index 10
    return lookup[t]

def tagReloc(fp, size, machine=''):
    end = fp.tell() + size
    while fp.tell() < end:
        #print "end is: 0x%X and tell is: 0x%X" % (end, fp.tell())
        oBlockStart = fp.tell()

        # peek on VirtualAddress and SizeOfBlock
        if uint64(fp, True) == 0:
            print('[0x%X,0x%X) raw reloc block NULL' % (oBlockStart, oBlockStart+8))
            break;

        VirtualAddress = tagUint32(fp, "VirtualAddress")
        SizeOfBlock = tagUint32(fp, "SizeOfBlock")
        nEntries = (SizeOfBlock-8)//2
        print('[0x%X,0x%X) raw reloc block 0x%X (%d entries)' % \
          (oBlockStart, oBlockStart+SizeOfBlock, VirtualAddress, nEntries))

        for i in range(nEntries):
            toto = uint16(fp, True)
            rtype = (toto&0xF000)>>12
            rtypeStr = relocTypeToStr(rtype)
            roffs = toto&0xFFF
            tag(fp, 2, "reloc entry %d=%s offset=0x%X" % (rtype,rtypeStr,roffs))

def tagPdata(fp, size, machine=''):
    if machine=='x64':
        # struct RUNTIME_FUNCTION is 4+4+4 (begin addr, end addr, unwind info)
        assert size % 12 == 0, 'size was 0x%X (%d) and is not divisible by 12' % (size, size)
        current = 0
        total = size // 12
        while current < total:
            tag(fp, 12, "struct RUNTIME_FUNCTION %d/%d" % (current+1, total), True)
            tagUint32(fp, 'BeginAddress')
            tagUint32(fp, 'EndAddress')
            tagUint32(fp, 'UnwindInfoAddress')
            current += 1

def tag_image_dos_header(fp):
    result = {}

    oHdr = fp.tell()
    e_magic = tag(fp, 2, "e_magic")
    assert e_magic == b'MZ'
    tagUint16(fp, "e_cblp")
    tagUint16(fp, "e_cp")
    tagUint16(fp, "e_crlc")
    tagUint16(fp, "e_cparhdr")
    tagUint16(fp, "e_minalloc")
    tagUint16(fp, "e_maxalloc")
    tagUint16(fp, "e_ss")
    tagUint16(fp, "e_sp")
    tagUint16(fp, "e_csum")
    tagUint16(fp, "e_eip")
    tagUint16(fp, "e_cs")
    tagUint16(fp, "e_lfarlc")
    tagUint16(fp, "e_ovno")
    tag(fp, 8, "e_res");
    tagUint16(fp, "e_oemid")
    tagUint16(fp, "e_oeminfo")
    tag(fp, 20, "e_res2");
    result['e_lfanew'] = tagUint32(fp, "e_lfanew")
    print("[0x%X,0x%X) raw image_dos_header" % \
        (oHdr, fp.tell()))
    return result

# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
def tag_image_file_header(fp, bits):
    assert bits in {32, 64}

    result = {}

    start = fp.tell()

    result['Machine'] = tagUint16(fp, "Machine", lambda x: '(%s)' % enum_int_to_name(IMAGE_FILE_MACHINE, x))
    result['NumberOfSections'] = tagUint16(fp, 'NumberOfSections')
    result['TimeDateStamp'] = tagUint32(fp, 'TimeDateStamp')
    result['PointerToSymbolTable'] = tagUint32(fp, 'PointerToSymbolTable')
    result['NumberOfSymbols'] = tagUint32(fp, 'NumberOfSymbols')
    result['SizeOfOptionalHeader'] = tagUint16(fp, 'SizeOfOptionalHeader')
    result['Characteristics'] = tagUint16(fp, 'Characteristics')

    tagFromPosition(fp, start, f'image_file_header{bits}')

    return result

def tag_image_data_directory(fp, comment):
    tag(fp, IMAGE_SIZEOF_IMAGE_DATA_DIRECTORY, 'IMAGE_DATA_DIRECTORY', comment, True)
    a = tagUint32(fp, "VirtualAddress")
    b = tagUint32(fp, "Size")
    return {'VirtualAddress':a, 'Size':b}

# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
def tag_image_optional_header(fp, bits):
    assert bits in {32, 64}

    result = {'data_directory':[]}

    start = fp.tell()

    result['Magic'] = tagUint16(fp, "Magic")

    if bits == 32:
        assert result['Magic'] == IMAGE_NT_OPTIONAL_HDR32_MAGIC
    elif bits == 64:
        assert result['Magic'] == IMAGE_NT_OPTIONAL_HDR64_MAGIC

    tagUint8(fp, "MajorLinkerVersion")
    tagUint8(fp, "MinorLinkerVersion")
    tagUint32(fp, "SizeOfCode")
    tagUint32(fp, "SizeOfInitializedData")
    tagUint32(fp, "SizeOfUninitializedData")
    tagUint32(fp, "AddressOfEntryPoint")
    tagUint32(fp, "BaseOfCode")

    if bits == 32:
        tagUint32(fp, "BaseOfData")
    else:
        # removed in 64-bit
        pass

    tagUint32(fp, "ImageBase")
    tagUint32(fp, "SectionAlignment")
    tagUint32(fp, "FileAlignment")
    tagUint16(fp, "MajorOperatingSystemVersion")
    tagUint16(fp, "MinorOperatingSystemVersion")
    tagUint16(fp, "MajorImageVersion")
    tagUint16(fp, "MinorImageVersion")
    tagUint16(fp, "MajorSubsystemVersion")
    tagUint16(fp, "MinorSubsystemVersion")
    tagUint32(fp, "Win32VersionValue")
    tagUint32(fp, "SizeOfImage")
    tagUint32(fp, "SizeOfHeaders")
    tagUint32(fp, "CheckSum")
    tagUint16(fp, "Subsystem")
    tagUint16(fp, "DllCharacteristics")

    if bits == 32:
        tagUint32(fp, "SizeOfStackReserve")
        tagUint32(fp, "SizeOfStackCommit")
        tagUint32(fp, "SizeOfHeapReserve")
        tagUint32(fp, "SizeOfHeapCommit")
    else:
        tagUint64(fp, "SizeOfStackReserve")
        tagUint64(fp, "SizeOfStackCommit")
        tagUint64(fp, "SizeOfHeapReserve")
        tagUint64(fp, "SizeOfHeapCommit")

    tagUint32(fp, "LoaderFlags")
    tagUint32(fp, "NumberOfRvaAndSizes")

    # IMAGE_DATA_DIRECTORY entries
    size = IMAGE_NUMBEROF_DIRECTORY_ENTRIES * IMAGE_SIZEOF_IMAGE_DATA_DIRECTORY
    tag(fp, size, 'DataDirectory', '', True)
    for i in range(IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
        comment = 'entry[%d] %s' % (i, enum_int_to_name(IMAGE_DIRECTORY_ENTRY, i))
        idd = tag_image_data_directory(fp, comment)
        result['data_directory'].append(idd)

    tagFromPosition(fp, start, f'image_optional_header{bits}')

    return result

# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64
#
# image_nt_headers
#   signature (4)
#   image_file_header (struct)
#     ...
#   image_optional_header (struct)
#     ...
#     data directory
def tag_image_nt_headers(fp, bits):
    assert bits in {32, 64}

    result = {}

    start = fp.tell()

    tagUint32(fp, "signature")

    result['image_file_header_offs'] = fp.tell()
    result['image_file_header'] = tag_image_file_header(fp, bits)

    result['image_optional_header_offs'] = fp.tell()
    result['image_optional_header'] = tag_image_optional_header(fp, bits)

    tagFromPosition(fp, start, f'image_nt_headers{bits}')

    return result

def tag_section_header(fp):
    result = {}

    start = fp.tell()

    result['Name'] = tagString(fp, IMAGE_SIZEOF_SHORT_NAME, "Name").rstrip()
    result['VirtualSize'] = tagUint32(fp, "VirtualSize")
    result['VirtualAddress'] = tagUint32(fp, "VirtualAddress")
    result['SizeOfRawData'] = tagUint32(fp, "SizeOfRawData")
    result['PointerToRawData'] = tagUint32(fp, "PointerToRawData")
    tagUint32(fp, "PointerToRelocations")
    tagUint32(fp, "PointerToLineNumbers")
    tagUint16(fp, "NumberOfRelocations")
    tagUint16(fp, "NumberOfLineNumbers")
    tagUint32(fp, "Characteristics")

    tagFromPosition(fp, start, 'image_section_header \"%s\"' % result['Name'])

    return result

def tag_section_headers(fp, n):
    result = []
    for i in range(n):
        section = tag_section_header(fp)
        result.append(section)
    return result

# resolve an RVA to an offset within the file
def rva_to_file_offset(rva, scnhdrs):
    for hdr in scnhdrs:
        if hdr['VirtualAddress'] <= rva < (hdr['VirtualAddress'] + hdr['VirtualSize']):
            # get offset within this section
            delta = rva - hdr['VirtualAddress']

            # is that raw data available in the section contents?
            if delta < hdr['SizeOfRawData']:
                return hdr['PointerToRawData'] + delta

# MS tools: dumpbin, ildasm, corflags
# https://jstdev.wordpress.com/2014/02/16/clr-header/
# https://github.com/kimperator/NinjectLib/blob/master/IATModifier.cpp
# https://pan-unit42.github.io/dotnetfile/api_documentation/header/cor20/
# https://github.com/pan-unit42/dotnetfile
def tag_image_cor20_header(fp):
    start = fp.tell()

    tagUint32(fp, 'cb (size)')

    # usually 2, 5
    # can be set to 2, 0 with RevertCLRHeader flag to corflags tool
    tagUint16(fp, 'MajorRuntimeVersion') # usually 2
    tagUint16(fp, 'MinorRuntimeVersion') # usually 5
    tag_image_data_directory(fp, 'MetaData')
    Flags = tagUint32(fp, 'Flags', lambda x: flags_string(COMIMAGE_FLAGS, x))

    # "pure IL executables trigger more restrictive PE header checks"

    if Flags & COMIMAGE_FLAGS.NATIVE_ENTRYPOINT.value:
        # native entrypoint
        tagUint32(fp, 'EntryPointRVA')
    else:
        # managed entrypoint
        tagUint32(fp, 'EntryPointToken')

    tag_image_data_directory(fp, 'Resources')
    tag_image_data_directory(fp, 'CodeManagerTable')
    tag_image_data_directory(fp, 'VTableFixups')
    tag_image_data_directory(fp, 'ExportAddressTableJumps')
    tag_image_data_directory(fp, 'ManagedNativeHeader')

    tagFromPosition(fp, start, 'image_cor20_header')
