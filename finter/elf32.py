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

def tag_elf32_sym(fp, index, strTab:StringTable):
    base = fp.tell()

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
    fp.seek(base)
    tag(fp, SIZEOF_ELF32_SYM, "Elf32_Sym \"%s\" (index:%d)" % (nameStr, index))

def tag_elf32_dyn(fp, e_machine):
    base = fp.tell()
    d_tag = uint32(fp, 1)
    tagStr = dynamic_type_tostr(d_tag, e_machine)
    tag(fp, 4, "d_tag:0x%X (%s)" % (d_tag, tagStr))
    tagUint32(fp, "val_ptr")
    fp.seek(base)
    tag(fp, SIZEOF_ELF32_DYN, "Elf32_Dyn (%s)" % tagStr)

    return d_tag != DynamicType.DT_NULL

def tag_elf32_shdr(fp, index, scnStrTab):
    base = fp.tell()

    sh_name = tagUint32(fp, "sh_name")
    sh_type = uint32(fp, 1)
    tag(fp, 4, "sh_type=0x%X (%s)" % \
        (sh_type, sh_type_tostr(sh_type)))
    sh_flags = uint32(fp, 1)
    tag(fp, 4, "sh_flags=0x%X (%s)" % \
        (sh_flags, sh_flags_tostr(sh_flags)))
    sh_addr = tagUint32(fp, "sh_addr")
    sh_offset = tagUint32(fp, "sh_offset")
    sh_size = tagUint32(fp, "sh_size")
    sh_link = tagUint32(fp, "sh_link") # usually the section index of the associated string or symbol table
    sh_info = tagUint32(fp, "sh_info") # usually the section index of the section to which this applies
    sh_addralign = tagUint32(fp, "sh_addralign")
    sh_entsize = tagUint32(fp, "sh_entsize")

    fp.seek(base)
    tag(fp, 40, 'elf32_shdr "%s" %s (index: %d)' % \
        (scnStrTab[sh_name], sh_type_tostr(sh_type), index))

    return {'sh_name':sh_name,
            'sh_type':sh_type,
            'sh_flags':sh_flags,
            'sh_addr':sh_addr,
            'sh_offset':sh_offset,
            'sh_size':sh_size,
            'sh_link':sh_link,
            'sh_info':sh_info,
            'sh_addralign':sh_addralign,
            'sh_entsize':sh_entsize}

def tag_elf32_phdr(fp, index):
    base = fp.tell()

    p_type = uint32(fp, True)
    tagUint32(fp, 'p_type', '('+phdr_type_tostr(p_type)+')')
    p_offset = tagUint32(fp, "p_offset")
    p_vaddr = tagUint32(fp, "p_vaddr")
    p_paddr = tagUint32(fp, "p_paddr")
    p_filesz = tagUint32(fp, "p_filesz")
    p_memsz = tagUint32(fp, "p_memsz")
    p_flags = uint32(fp, True)
    tagUint32(fp, 'p_flags', '('+phdr_flags_tostr(p_flags)+')')
    p_align = tagUint32(fp, "p_align")

    print('[0x%X,0x%X) raw elf32_phdr index=%d' % \
        (base, fp.tell(), index))

    return {    'p_type':p_type,
                'p_offset':p_offset,
                'p_vaddr':p_vaddr,
                'p_paddr':p_paddr,
                'p_filesz':p_filesz,
                'p_memsz':p_memsz,
                'p_flags':p_flags,
                'p_align':p_align   }

def analyze(fp):
    if not isElf32(fp):
           return

    # read elf32_hdr
    tag(fp, SIZEOF_ELF32_HDR, "elf32_hdr", 1)
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
    assert(e_ehsize == SIZEOF_ELF32_HDR)
    tagUint16(fp, "e_phentsize")
    e_phnum = tagUint16(fp, "e_phnum")
    e_shentsize = tagUint16(fp, "e_shentsize")
    assert(e_shentsize == 0 or e_shentsize == SIZEOF_ELF32_SHDR)
    e_shnum = tagUint16(fp, "e_shnum")
    e_shstrndx = tagUint16(fp, "e_shstrndx")

    # read the string table
    tmp = e_shoff + e_shstrndx*SIZEOF_ELF32_SHDR
    #print('seeking to %X for the string table section header' % tmp)
    fp.seek(tmp)
    fmt = {ELFDATA2LSB:'<IIIIII', ELFDATA2MSB:'>IIIIII'}[ei_data]
    (a,b,c,d,sh_offset,sh_size) = struct.unpack(fmt, fp.read(24))
    #print('sh_offset: %08X, sh_size: %08X' % (sh_offset, sh_size))
    fp.seek(sh_offset)
    scnStrTab = StringTable(fp, sh_size)

    # tag and save all section headers
    fp.seek(e_shoff)
    scn_infos = []
    for i in range(e_shnum):
        info:dict = tag_elf32_shdr(fp, i, scnStrTab)
        scn_infos.append(info)

    # tag section contents
    for i, info in enumerate(scn_infos):
        # top level container
        if not info['sh_type'] in [SHT_NULL, SHT_NOBITS] and info['sh_size'] > 0:
            print('[0x%X,0x%X) raw section "%s" contents' % \
                (info['sh_offset'], info['sh_offset']+info['sh_size'], scnStrTab[info['sh_name']]))

        # like .dynamic
        if info['sh_type'] == SHT_DYNAMIC:
            # array of Elf32_Dyn entries
            fp.seek(info['sh_offset'])
            while fp.tell() < (info['sh_offset'] + info['sh_size']):
                if not tag_elf32_dyn(fp, e_machine):
                    break

        # like .dynsym
        elif info['sh_type'] in [SHT_SYMTAB, SHT_DYNSYM]:
            # get associated string table
            link = info['sh_link']
            fp.seek(scn_infos[link]['sh_offset'])
            strtab = StringTable(fp, scn_infos[link]['sh_size'])
            # array of Elf32_Sym entries
            idx = 0
            fp.seek(info['sh_offset'])
            while fp.tell() < (info['sh_offset'] + info['sh_size']):
                tag_elf32_sym(fp, idx, strtab)
                idx += 1

        elif info['sh_type'] == SHT_STRTAB:
            fp.seek(info['sh_offset'])
            tag_strtab(fp, info['sh_size'])

        elif info['sh_type'] == SHT_REL:
            fp.seek(info['sh_offset'])
            while fp.tell() < (info['sh_offset'] + info['sh_size']):
                tag_elf32_rel(fp, e_machine)

        elif info['sh_type'] == SHT_RELA:
            fp.seek(info['sh_offset'])
            while fp.tell() < (info['sh_offset'] + info['sh_size']):
                tag_elf32_rela(fp, e_machine)

    # read program headers
    # REMINDER! struct member 'p_flags' changes between 32/64 bits
    fp.seek(e_phoff)
    phdr_infos = []
    for i in range(e_phnum):
        info:dict = tag_elf32_phdr(fp, i)
        phdr_infos.append(info)

    for i, info in enumerate(phdr_infos):
        start = info['p_offset']
        end = start + info['p_filesz']


        # top level container
        if not (start and end):
            continue

        type_str = phdr_type_tostr(info['p_type'])

        print('[0x%X,0x%X) raw segment idx:%d type:%s' % \
            (start, end, i, type_str))

        # If a dynamic program header / segment exists, but it wasn't tagged in a section,
        # tag it now. Some toolchains produce section-less binaries.
        if info['p_type'] == PT_DYNAMIC:
            if not [si for si in scn_infos if si['sh_type'] == SHT_DYNAMIC]:
                fp.seek(start)

                while fp.tell() < end:
                    if not tag_elf32_dyn(fp, e_machine):
                        break

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
