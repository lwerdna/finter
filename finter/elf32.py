#!/usr/bin/env python3

import sys
import struct
import binascii

from .elf import *
from .helpers import *

#typedef struct {
#        Elf32_Addr      r_offset;
#        Elf32_Word      r_info;
#} Elf32_Rel;
def tag_elf32_rel(fp, machine:E_MACHINE=None):
    tag(fp, 8, 'Elf32_Rel', 1)

    #r_offset = uint32(fp, 1)
    tagUint32(fp, 'r_offset') # location relocation is applied
                           # - relocated file: section offset
                           # - executable/shared object: virtual address
    r_info = uint32(fp, 1)
    r_sym = ELF32_R_SYM(r_info)
    r_type = ELF32_R_TYPE(r_info)
    r_type_str = ''
    if machine == E_MACHINE.EM_ARM.value:
        r_type_str = ' %s' % RELOC_TYPE_ARM(r_type).name
    descr = 'r_info=%08X (sym=%06X type=%02X%s)' % \
        (r_info, r_sym, r_type, r_type_str)
    tag(fp, 4, descr)   # relocation type and symbol table index
                           # - eg: R_SPARC_GOT10, R_386_PLT32, R_AMD64_JUMP_SLOT

#typedef struct {
#        Elf32_Addr      r_offset;
#        Elf32_Word      r_info;
#        Elf32_Sword     r_addend;
#} Elf32_Rela;
def tag_elf32_rela(fp):
    tag(fp, 12, 'Elf32_Rela', 1)
    tag(fp, 4, 'r_offset')
    tag(fp, 4, 'r_info')
    tag(fp, 4, 'r_addend')

# get symbol table index from r_info
#define ELF32_R_SYM(info)             ((info)>>8)
def ELF32_R_SYM(info):
    return (info >> 8) & 0xFFFFFF

# get symbol type from r_info
#define ELF32_R_TYPE(info)            ((unsigned char)(info))
def ELF32_R_TYPE(info):
    return info & 0xFF

def analyze(fp):
    if not isElf32(fp):
           return

    # read elf32_hdr
    tag(fp, SIZE_ELF32_HDR, "elf32_hdr", 1)
    tag(fp, 4, "e_ident[0..4)")
    tagUint8(fp, "e_ident[EI_CLASS] (32-bit)")
    ei_data = uint8(fp, 1)
    tagUint8(fp, "e_ident[EI_DATA] %s" % ei_data_tostr(ei_data))
    assert(ei_data in [ELFDATA2LSB,ELFDATA2MSB])
    if ei_data == ELFDATA2LSB:
        setLittleEndian()
    elif ei_data == ELFDATA2MSB:
        setBigEndian()
    tagUint8(fp, "e_ident[EI_VERSION]")
    tagUint8(fp, "e_ident[EI_OSABI]")
    tagUint8(fp, "e_ident[EI_ABIVERSION]")
    tag(fp, 7, "e_ident[EI_PAD]")
    e_type = uint16(fp, 1)
    tagUint16(fp, "e_type %s" % e_type_tostr(e_type))
    e_machine = uint16(fp, 1)
    tagUint16(fp, "e_machine %s" % (e_machine_tostr(e_machine)))
    tagUint32(fp, "e_version")
    tagUint32(fp, "e_entry")
    e_phoff = tagUint32(fp, "e_phoff")
    e_shoff = tagUint32(fp, "e_shoff")
    tagUint32(fp, "e_flags")
    e_ehsize = tagUint16(fp, "e_ehsize")
    assert(e_ehsize == SIZE_ELF32_HDR)
    tagUint16(fp, "e_phentsize")
    e_phnum = tagUint16(fp, "e_phnum")
    e_shentsize = tagUint16(fp, "e_shentsize")
    assert(e_shentsize == SIZE_ELF32_SHDR)
    e_shnum = tagUint16(fp, "e_shnum")
    e_shstrndx = tagUint16(fp, "e_shstrndx")

    # read the string table
    tmp = e_shoff + e_shstrndx*SIZE_ELF32_SHDR
    #print('seeking to %X for the string table section header' % tmp)
    fp.seek(tmp)
    fmt = {ELFDATA2LSB:'<IIIIII', ELFDATA2MSB:'>IIIIII'}[ei_data]
    (a,b,c,d,sh_offset,sh_size) = struct.unpack(fmt, fp.read(24))
    #print('sh_offset: %08X, sh_size: %08X' % (sh_offset, sh_size))
    fp.seek(sh_offset)
    scnStrTab = StringTable(fp, sh_size)

    # read all section headers
    dynamic = None
    symtab = None
    strtab = None
    reloc_sections = [] # [(offset, size)]
    reloca_sections = []
    fp.seek(e_shoff)
    for i in range(e_shnum):
        oHdr = fp.tell()
        sh_name = tagUint32(fp, "sh_name")
        sh_type = uint32(fp, 1)
        tag(fp, 4, "sh_type=0x%X (%s)" % \
            (sh_type, sh_type_tostr(sh_type)))
        sh_flags = uint32(fp, 1)
        tag(fp, 4, "sh_flags=0x%X (%s)" % \
            (sh_flags, sh_flags_tostr(sh_flags)))
        tagUint32(fp, "sh_addr")
        sh_offset = tagUint32(fp, "sh_offset")
        sh_size = tagUint32(fp, "sh_size")
        tagUint32(fp, "sh_link")
        tagUint32(fp, "sh_info")
        tagUint32(fp, "sh_addralign")
        tagUint32(fp, "sh_entsize")

        strType = sh_type_tostr(sh_type)
        strName = scnStrTab[sh_name]

        # store info on special sections
        if strName == '.dynamic':
            dynamic = [sh_offset, sh_size]
        if strName == '.symtab':
            symtab = [sh_offset, sh_size]
        if strName == '.strtab':
            strtab = [sh_offset, sh_size]
        if sh_type == SHT_REL:
            reloc_sections.append((sh_offset, sh_size))
        if sh_type == SHT_RELA:
            reloca_sections.append((sh_offset, sh_size))

        print('[0x%X,0x%X) elf32_shdr "%s" %s (index: %d)' % \
            (oHdr, fp.tell(), scnStrTab[sh_name], strType, i))

        if not sh_type in [SHT_NULL, SHT_NOBITS] and sh_size > 0:
            print('[0x%X,0x%X) section "%s" contents' % \
                (sh_offset, sh_offset+sh_size, scnStrTab[sh_name]))

    # certain sections we analyze deeper...
    strTab = None
    if strtab:
        [offs,size] = strtab
        fp.seek(offs)
        strTab = StringTable(fp, size)

    for (offs, size) in reloc_sections:
        fp.seek(offs)
        while fp.tell() < offs + size:
            tag_elf32_rel(fp, e_machine)

    for (offs, size) in reloca_sections:
        fp.seek(offs)
        while fp.tell() < offs + size:
            tag_elf32_rela(fp, e_machine)

    if dynamic:
        # .dynamic is just an array of Elf32_Dyn entries
        [offs,size] = dynamic
        fp.seek(offs)
        while fp.tell() < (offs + size):
            tmp = fp.tell()
            d_tag = uint32(fp, 1)
            tagStr = dynamic_type_tostr(d_tag)
            tag(fp, 4, "d_tag:0x%X (%s)" % (d_tag, tagStr))
            tagUint32(fp, "val_ptr")
            fp.seek(tmp)
            tag(fp, SIZE_ELF32_DYN, "Elf32_Dyn (%s)" % tagStr)

            if d_tag == DT_NULL:
                break

    if symtab and strTab:
        # .symbtab is an array of Elf32_Sym entries
        [offs,size] = symtab
        fp.seek(offs)
        while fp.tell() < (offs + size):
            tmp = fp.tell()

            st_name = uint32(fp, 1)
            nameStr = strTab[st_name]
            tag(fp, 4, "st_name=0x%X \"%s\"" % (st_name,nameStr))

            st_value = tagUint32(fp, "st_value")

            st_size = tagUint32(fp, "st_size")

            st_info = uint8(fp, 1)
            bindingStr = symbol_binding_tostr(st_info >> 4)
            typeStr = symbol_type_tostr(st_info & 0xF)
            tag(fp, 1, "st_info bind:%d(%s) type:%d(%s)" % \
                (st_info>>4, bindingStr, st_info&0xF, typeStr))

            st_other = tagUint8(fp, "st_other")

            st_shndx = tagUint16(fp, "st_shndx")
            fp.seek(tmp)
            tag(fp, SIZE_ELF32_SYM, "Elf32_Sym \"%s\"" % nameStr)

    # read program headers
    fp.seek(e_phoff)
    for i in range(e_phnum):
        oHdr = fp.tell()
        p_type = tagUint32(fp, "p_type")
        tagUint32(fp, "p_flags")
        tagUint32(fp, "p_offset")
        tagUint32(fp, "p_vaddr")
        tagUint32(fp, "p_paddr")
        tagUint32(fp, "p_filesz")
        tagUint32(fp, "p_memsz")
        tagUint32(fp, "p_align")

        strType = phdr_type_tostr(p_type)

        print('[0x%X,0x%X) elf32_phdr %d %s' % \
            (oHdr, fp.tell(), i, strType))

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
