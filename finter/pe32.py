#!/usr/bin/env python

import sys
import struct
import binascii

from . import pe
from .helpers import *

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    if not (pe.idFile(fp) == "pe32"):
        return

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
    e_lfanew = tagUint32(fp, "e_lfanew")
    print("[0x%X,0x%X) raw image_dos_header" % \
        (oHdr, fp.tell()))
    
    # image_nt_headers has signature and two substructures
    fp.seek(e_lfanew)
    tagUint32(fp, "signature")
    # first substructure is image_file_header
    oIFH = fp.tell()
    Machine = tagUint16(fp, "Machine", lambda x: '(%s)' % enum_int_to_name(pe.IMAGE_FILE_MACHINE, x))
    assert Machine == pe.IMAGE_FILE_MACHINE.I386.value
    
    NumberOfSections = tagUint16(fp, "NumberOfSections")
    tagUint32(fp, "TimeDateStamp")
    PointerToSymbolTable = tagUint32(fp, "PointerToSymbolTable")
    NumberOfSymbols = tagUint32(fp, "NumberOfSymbols")
    SizeOfOptionalHeader = tagUint16(fp, "SizeOfOptionalHeader")
    tagUint16(fp, "Characteristics")
    print("[0x%X,0x%X) raw image_file_header" % \
        (oIFH, fp.tell()))
    # second substructure is image_optional_header
    oIOH = fp.tell()
    magic = tagUint16(fp, "Magic")
    assert magic == 0x10B;
    tagUint8(fp, "MajorLinkerVersion")
    tagUint8(fp, "MinorLinkerVersion")
    tagUint32(fp, "SizeOfCode")
    tagUint32(fp, "SizeOfInitializedData")
    tagUint32(fp, "SizeOfUninitializedData")
    tagUint32(fp, "AddressOfEntryPoint")
    tagUint32(fp, "BaseOfCode")
    tagUint32(fp, "BaseOfData")
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
    tagUint32(fp, "SizeOfStackReserve")
    tagUint32(fp, "SizeOfStackCommit")
    tagUint32(fp, "SizeOfHeapReserve")
    tagUint32(fp, "SizeOfHeapCommit")
    tagUint32(fp, "LoaderFlags")
    tagUint32(fp, "NumberOfRvaAndSizes")
    oDD = fp.tell()
    for i in range(pe.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
        oDE = fp.tell()
        tagUint32(fp, "VirtualAddress")
        tagUint32(fp, "Size")
        print("[0x%X,0x%X) DataDir %s" % \
            (oDE, fp.tell(), pe.dataDirIdxToStr(i)))
    print("[0x%X,0x%X) raw DataDirectory" % \
        (oDD, fp.tell()))
    print("[0x%X,0x%X) raw image_optional_header" % \
        (oIOH, fp.tell()))
    print("[0x%X,0x%X) raw image_nt_headers" % \
        (e_lfanew, fp.tell()))
    
    (oScnReloc, nScnReloc) = (None,None)
    fp.seek(oIOH + SizeOfOptionalHeader)
    for i in range(NumberOfSections):
        oISH = fp.tell()
        Name = tagString(fp, pe.IMAGE_SIZEOF_SHORT_NAME, "Name")
        tagUint32(fp, "VirtualSize");
        tagUint32(fp, "VirtualAddress");
        SizeOfRawData = tagUint32(fp, "SizeOfRawData")
        PointerToRawData = tagUint32(fp, "PointerToRawData")
        tagUint32(fp, "PointerToRelocations")
        tagUint32(fp, "PointerToLineNumbers")
        tagUint16(fp, "NumberOfRelocations")
        tagUint16(fp, "NumberOfLineNumbers")
        tagUint32(fp, "Characteristics")
        print("[0x%X,0x%X) image_section_header \"%s\"" % \
            (oISH, fp.tell(), Name.rstrip()))
        print("[0x%X,0x%X) section \"%s\" contents" % \
            (PointerToRawData, PointerToRawData+SizeOfRawData, Name.rstrip()))
    
        if Name=='.reloc\x00\x00':
            oScnReloc = PointerToRawData
            nScnReloc = SizeOfRawData
    
    if(oScnReloc):
        fp.seek(oScnReloc)
        pe.tagReloc(fp, nScnReloc)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
