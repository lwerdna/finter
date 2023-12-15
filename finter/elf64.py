#!/usr/bin/env python

import sys
import struct
import binascii

from . import dwarf
from .elf import *
from .helpers import *

#define ELF64_R_SYM(i)			((i) >> 32)
def ELF64_R_SYM(i):
    return i >> 32

#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
def ELF64_R_TYPE(i):
    return i & 0xFFFFFFFF

def ELF64_ST_BIND(info):
    return info >> 4

def ELF64_ST_TYPE(info):
    return info & 0xf

# typedef struct
# {
#     Elf64_Addr	r_offset;		/* Address */
#     Elf64_Xword	r_info;			/* Relocation type and symbol index */
#     Elf64_Sxword	r_addend;		/* Addend */
# } Elf64_Rela;
def tag_elf64_rela(fp, machine:E_MACHINE=None):
    tag(fp, 24, 'Elf64_Rela', True)
    tagUint64(fp, 'r_offset')

    # info is type.24|id.8
    r_info = uint64(fp, True)

    # this way? with ELF64_R_TYPE_DATA() and ELF64_R_TYPE_ID()
    if 0:
        data = (r_info & 0xFFFFFF00) >> 8
        id_ = r_info & 0xFF
        tagUint64(fp, 'r_info', f'data=0x{data:X} id=0x{id_:X}')
    # or this? with ELF64_R_SYM() and ELF64_R_TYPE()
    if 1:
        r_sym = ELF64_R_SYM(r_info)
        r_type = ELF64_R_TYPE(r_info)
        r_type_str = ''
        if machine == E_MACHINE.EM_AARCH64.value:
            r_type_str = ' (' + RELOC_TYPE_ARM64(r_type).name + ')'
        tagUint64(fp, 'r_info', f'sym=0x{r_sym:X} type=0x{r_type:X}{r_type_str}')

    tagInt64(fp, 'r_addend')

# typedef struct {
#         Elf64_Xword d_tag;
#         union {
#                 Elf64_Xword     d_val;
#                 Elf64_Addr      d_ptr;
#         } d_un;
# } Elf64_Dyn;
def tag_elf64_dyn(fp, e_machine):
    base = fp.tell()
    # tag d_tag
    d_tag = uint64(fp, 1)
    tag(fp, 8, "d_tag:0x%X (%s)" % (d_tag, dynamic_type_tostr(d_tag, e_machine)))
    # tag d_val/d_ptr
    d_val = tagUint64(fp, 'd_val')
    # tag root struct
    fp.seek(base)
    tag(fp, SIZE_ELF64_DYN, "Elf64_Dyn (%s)" % tag)
    # return
    return d_tag != DynamicType.DT_NULL

# typedef struct {
#         Elf64_Word      sh_name;
#         Elf64_Word      sh_type;
#         Elf64_Xword     sh_flags;
#         Elf64_Addr      sh_addr;
#         Elf64_Off       sh_offset;
#         Elf64_Xword     sh_size;
#         Elf64_Word      sh_link;
#         Elf64_Word      sh_info;
#         Elf64_Xword     sh_addralign;
#         Elf64_Xword     sh_entsize;
# } Elf64_Shdr;
def tag_elf64_shdr(fp, index, scnStrTab):
    base = fp.tell()

    sh_name = tagUint64(fp, "sh_name")
    sh_type = uint64(fp, 1)
    tag(fp, 4, "sh_type=0x%X (%s)" % \
        (sh_type, sh_type_tostr(sh_type)))
    sh_flags = uint64(fp, 1)
    tag(fp, 4, "sh_flags=0x%X (%s)" % \
        (sh_flags, sh_flags_tostr(sh_flags)))
    sh_addr = tagUint64(fp, "sh_addr")
    sh_offset = tagUint64(fp, "sh_offset")
    sh_size = tagUint64(fp, "sh_size")
    sh_link = tagUint64(fp, "sh_link") # usually the section index of the associated string or symbol table
    sh_info = tagUint64(fp, "sh_info") # usually the section index of the section to which this applies
    sh_addralign = tagUint64(fp, "sh_addralign")
    sh_entsize = tagUint64(fp, "sh_entsize")

    fp.seek(base)
    tag(fp, SIZE_ELF64_SHDR, 'elf32_shdr "%s" %s (index: %d)' % \
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

def tag_elf64_phdr(fp, index):
    base = fp.tell()

    p_type = uint32(fp, True)
    tagUint32(fp, 'p_type', '('+phdr_type_tostr(p_type)+')')
    p_flags = uint32(fp, True)
    tagUint32(fp, 'p_flags', '('+phdr_flags_tostr(p_flags)+')')
    p_offset = tagUint64(fp, 'p_offset')
    p_vaddr = tagUint64(fp, 'p_vaddr')
    p_paddr = tagUint64(fp, 'p_paddr')
    p_filesz = tagUint64(fp, 'p_filesz')
    p_memsz = tagUint64(fp, 'p_memsz')
    p_align = tagUint64(fp, 'p_align')

    print('[0x%X,0x%X) raw elf64_phdr index=%d' % \
        (base, fp.tell(), index))

    return {    'p_type':p_type,
                'p_offset':p_offset,
                'p_vaddr':p_vaddr,
                'p_paddr':p_paddr,
                'p_filesz':p_filesz,
                'p_memsz':p_memsz,
                'p_flags':p_flags,
                'p_align':p_align   }

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    if not isElf64(fp):
           return
    tag(fp, SIZE_ELF64_HDR, "elf64_hdr", 1)
    tag(fp, 4, "e_ident[0..4)")
    tagUint8(fp, "e_ident[EI_CLASS] (64-bit)")
    ei_data = uint8(fp, 1)
    tagUint8(fp, "e_ident[EI_DATA] %s" % ei_data_tostr(ei_data))
    assert(ei_data in [ELFDATA2LSB,ELFDATA2MSB])
    if ei_data == ELFDATA2LSB:
        setLittleEndian()
    elif ei_data == ELFDATA2MSB:
        setBigEndian()
    tagUint8(fp, "e_ident[EI_VERSION] (%s-end)" % ('little' if ei_data==ELFDATA2LSB else 'big'))
    tagUint8(fp, "e_ident[EI_OSABI]")
    tagUint8(fp, "e_ident[EI_ABIVERSION]")
    tag(fp, 7, "e_ident[EI_PAD]")
    assert fp.tell() == 16
    e_type = uint16(fp, 1)
    tagUint16(fp, "e_type %s" % e_type_tostr(e_type))
    e_machine = uint16(fp, 1)
    tagUint16(fp, "e_machine %s" % (e_machine_tostr(e_machine)))
    tagUint32(fp, "e_version")
    tagUint64(fp, "e_entry")
    e_phoff = tagUint64(fp, "e_phoff")
    e_shoff = tagUint64(fp, "e_shoff")
    tagUint32(fp, "e_flags")
    tagUint16(fp, "e_ehsize")
    tagUint16(fp, "e_phentsize")
    e_phnum = tagUint16(fp, "e_phnum")
    tagUint16(fp, "e_shentsize")
    e_shnum = tagUint16(fp, "e_shnum")
    e_shstrndx = tagUint16(fp, "e_shstrndx")

    # read the string table
    fp.seek(e_shoff + e_shstrndx*SIZE_ELF64_SHDR)
    tmp = fp.tell()
    fmt = {ELFDATA2LSB:'<IIQQQQ', ELFDATA2MSB:'>IIQQQQ'}[ei_data]
    (a,b,c,d,sh_offset,sh_size) = struct.unpack(fmt, fp.read(40))
    fp.seek(sh_offset)
    scnStrTab = StringTable(fp, sh_size)

    # tag and save all section headers
    fp.seek(e_shoff)
    scn_infos = []
    for i in range(e_shnum):
        info:dict = tag_elf64_shdr(fp, i, scnStrTab)
        scn_infos.append(info)

    dynamic = None
    symtab = None
    strtab = None
    debug_info = None
    debug_abbrev = None
    rela_sections = []

    # tag section contents
    for i, info in enumerate(scn_infos):
        fp.seek(info['sh_offset'])

        strName = scnStrTab[info['sh_name']]

        # store info on special sections
        if strName == '.dynamic':
            dynamic = [sh_offset, sh_size]
        if strName == '.symtab':
            symtab = [sh_offset, sh_size]
        if strName == '.strtab':
            strtab = [sh_offset, sh_size]
        if strName == '.opd':
            opd = [sh_offset, sh_size, sh_addr]
        if strName == '.debug_info':
            debug_info = [sh_offset, sh_size]
        if strName == '.debug_abbrev':
            debug_abbrev = [sh_offset, sh_size]
        if sh_type == SHT_RELA:
            rela_sections.append((sh_offset, sh_size))

        if (not sh_type in [SHT_NULL, SHT_NOBITS]):
            print('[0x%X,0x%X) raw section "%s" contents' % \
                (sh_offset, sh_offset+sh_size, scnStrTab[sh_name]))

    # certain sections we analyze deeper...
    if strtab:
        [offs,size] = strtab
        fp.seek(offs)
        strTab = StringTable(fp, size)

    if dynamic:
        # .dynamic is just an array of Elf64_Dyn entries
        [offs,size] = dynamic
        fp.seek(offs)
        while fp.tell() < (offs + size):
            if not tag_elf64_dyn(fp, e_machine):
                break;

    symtab_name2addr = {}
    symtab_addr2name = {}
    if symtab:
        # .symbtab is an array of Elf64_Sym entries
        # note that Elf64_Sym differs from Elf32_Sym beyond field sizes
        [offs,size] = symtab
        fp.seek(offs)
        while fp.tell() < (offs + size):
            tmp = fp.tell()
            st_name = uint32(fp, 1)
            nameStr = strTab[st_name]
            tag(fp, 4, "st_name=0x%X \"%s\"" % (st_name,nameStr))
            st_info = uint8(fp, 1)
            bindingStr = symbol_binding_tostr(ELF64_ST_BIND(st_info))
            typeStr = symbol_type_tostr(ELF64_ST_TYPE(st_info))
            tag(fp, 1, "st_info bind:%d(%s) type:%d(%s)" % \
                (st_info>>4, bindingStr, st_info&0xF, typeStr))
            st_other = tagUint8(fp, "st_other")
            st_shndx = tagUint16(fp, "st_shndx")
            st_value = tagUint64(fp, "st_value")
            st_size = tagUint64(fp, "st_size")
            fp.seek(tmp)
            tag(fp, SIZE_ELF64_SYM, "Elf64_Sym \"%s\"" % nameStr)

            symtab_name2addr[nameStr] = st_value
            symtab_addr2name[st_value] = nameStr

    opd = False
    if opd and E_MACHINE(e_machine) == E_MACHINE.EM_PPC64:
        [offs, size, scn_vaddr_base] = opd
        fp.seek(offs)
        func_descr_idx = 0
        while fp.tell() < (offs + size):
            tmp = fp.tell()
            tagUint64(fp, "entry")
            tagUint64(fp, "toc")
            tagUint64(fp, "environ")

            vaddr = scn_vaddr_base + (tmp - offs)

            fp.seek(tmp)
            if vaddr in symtab_addr2name:
                tag(fp, 24, "descriptor \"%s\"" % symtab_addr2name[vaddr])
            else:
                tag(fp, 24, "descriptor %d" % func_descr_idx)

            func_descr_idx += 1

    if debug_info:
        [scn_addr, scn_sz] = debug_info
        fp.seek(scn_addr)

        while fp.tell() < (scn_addr + scn_sz):
            cu_base = fp.tell()

            fp.seek(cu_base)
            (len_header, len_body) = dwarf.tag_compilation_unit_header(fp)

            fp.seek(cu_base + len_header)
            tag(fp, len_body, 'compilation unit contents', True)

            #tagUleb128(fp, "abbrev_code")

            fp.seek(cu_base + len_header + len_body)

    if debug_abbrev:
        [scn_addr, scn_sz] = debug_abbrev
        fp.seek(scn_addr)
        dwarf.tag_debug_abbrev(fp, scn_addr, scn_sz)

    for (addr, size) in rela_sections:
        fp.seek(addr)
        while fp.tell() < addr + size:
            tag_elf64_rela(fp, e_machine)

    # read program headers
    # REMINDER! struct member 'p_flags' changes between 32/64 bits
    fp.seek(e_phoff)
    phdr_infos = []
    for i in range(e_phnum):
        info:dict = tag_elf64_phdr(fp, i)
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
                    if not tag_elf64_dyn(fp, e_machine):
                        break

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
