# finter
decompose files into offset intervals

The programs ("dissectors") in ./finter like `./finter/elf32.py` read a file and print on stdout information:

    [0x0,0x34) elf32_hdr
    [0x0,0x4) e_ident[0..4)
    [0x4,0x5) e_ident[EI_CLASS] (32-bit)=0x1
    [0x5,0x6) e_ident[EI_DATA] MSB (big-end)=0x2
    [0x6,0x7) e_ident[EI_VERSION]=0x1
    [0x7,0x8) e_ident[EI_OSABI]=0x0
    [0x8,0x9) e_ident[EI_ABIVERSION]=0x0
    [0x9,0x10) e_ident[EI_PAD]
    [0x10,0x12) e_type=0x2
    [0x12,0x14) e_machine=0x8
    ...
It is all very simple plaintext. The two parts are the memory range and the text of the interval. Intervals are separated by newlines.

Dissectors do not have to worry about ordering intervals or providing hierarchical information. External programs that consume the intervals can derive all of that.

## example users of intervals

 `./raw.py` just relays the intervals to stdout which can be useful for debugging.

`./tree.py` uses interval trees to determine hierarchical information and presents a text representation:

```
00000000: (0x40) elf64_hdr
00000000:   (4) e_ident[0..4)
00000004:   (1) e_ident[EI_CLASS] (64-bit)=0x2
00000005:   (1) e_ident[EI_DATA] LSB (little-end)=0x1
00000006:   (1) e_ident[EI_VERSION] (little-end)=0x1
00000007:   (1) e_ident[EI_OSABI]=0x0
00000008:   (1) e_ident[EI_ABIVERSION]=0x0
00000009:   (7) e_ident[EI_PAD]
00000010:   (2) e_type=0x2
00000012:   (2) e_machine=0x3E
00000014:   (4) e_version=0x1
00000018:   (8) e_entry=0x400B38
00000020:   (8) e_phoff=0x40
00000028:   (8) e_shoff=0xED690
00000030:   (4) e_flags=0x0
00000034:   (2) e_ehsize=0x40
00000036:   (2) e_phentsize=0x38
00000038:   (2) e_phnum=0x3
0000003A:   (2) e_shentsize=0x40
0000003C:   (2) e_shnum=0xC
0000003E:   (2) e_shstrndx=0xB
00000040: (0x38) elf64_phdr 0 PT_LOAD
00000040:   (4) p_type=0x1
00000044:   (4) p_flags=0x5
00000048:   (8) p_offset=0x0
00000050:   (8) p_vaddr=0x400000
00000058:   (8) p_paddr=0x400000
00000060:   (8) p_filesz=0xE61E3
00000068:   (8) p_memsz=0xE61E3
00000070:   (8) p_align=0x200000
```

