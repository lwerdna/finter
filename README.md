# finter
This is an approach to file decomposition

Decompose files into offset intervals. The modules in `./finter` like `./finter/elf32.py` read a file and print on stdout information with the following syntax:

```
<interval> <type> <text>
```

For example:

```
[0x0,0x40) raw elf64_hdr
```

This means the bytes in interval `[0x0,0x40)`, have type `raw`, and should be associated with text `elf64_hdr`.

Another example:

```
[0x12,0x14) <H e_machine EM_X86_64=0x3E
```

This means the byte in interval `[0x4, 0x5)` has type `<H` (a little-endian ordered halfword) and should be associated with text `e_machine EM_X86_64=0x3E`.

Multiple of these tags can annotate a full struct:

      [0x0,0x40) raw elf64_hdr
      [0x0,0x4) raw e_ident[0..4)
      [0x4,0x5) <B e_ident[EI_CLASS] (64-bit)=0x2
      [0x5,0x6) <B e_ident[EI_DATA] LSB (little-end)=0x1
      [0x6,0x7) <B e_ident[EI_VERSION] (little-end)=0x1
      [0x7,0x8) <B e_ident[EI_OSABI]=0x0
      [0x8,0x9) <B e_ident[EI_ABIVERSION]=0x0
      [0x9,0x10) raw e_ident[EI_PAD]
      [0x10,0x12) <H e_type ET_EXEC=0x2
      [0x12,0x14) <H e_machine EM_X86_64=0x3E
    ...
Dissectors do not have to worry about ordering or providing hierarchical information. External programs that consume the intervals can derive all of that.

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

`./oha.py` tries to annotate a traditional hex dump with the interval data:

```
...
                                                                             elf32_phdr 8 OS
00000130:             52 E5 74 64                              R.td             p_type=0x6474E552
00000130:                         20 0F 00 00                       ...         p_flags=0xF20
00000130:                                     20 0F 41 00               .A.     p_offset=0x410F20
00000140: 20 0F 41 00                                       .A.                 p_vaddr=0x410F20
00000140:             E0 00 00 00                              ....             p_paddr=0xE0
00000140:                         E0 00 00 00                      ....         p_filesz=0xE0
00000140:                                     04 00 00 00              ....     p_memsz=0x4
00000150: 01 00 00 00                                      ....                 p_align=0x1

00000150:             2F 6C 69 62 2F 6C 64 2D 6C 69 6E 75      /lib/ld-linu   section ".interp" contents
00000160: 78 2E 73 6F 2E 32 00                             x.so.2.
00000160:                         04 00 00 00 14 00 00 00          ........   section ".note.gnu.build-id" contents
00000170: 03 00 00 00 47 4E 55 00 36 E9 00 E1 96 63 0D F0  ....GNU.6....c..
00000180: B2 28 54 CE 96 CF FD 80 7B C5 06 A8              .(T.....{...
00000180:                                     03 00 00 00              ....   section ".hash" contents
00000190: 07 00 00 00 01 00 00 00 05 00 00 00 04 00 00 00  ................
000001A0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001B0: 03 00 00 00 06 00 00 00 02 00 00 00              ............
000001B0:                                     03 00 00 00              ....   section ".gnu.hash" contents
000001C0: 02 00 00 00 01 00 00 00 05 00 00 00 20 48 03 21  ............ H.!
000001D0: 02 00 00 00 03 00 00 00 06 00 00 00 11 7B 9C 7C  .............{.|
000001E0: B8 2B 6B 15 7C ED 11 0F B1 DC 6B 14 2F 4E 3D F6  .+k.|.....k./N=.
000001F0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................   section ".dynsym" contents
00000200: 48 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00  H........... ...
00000210: 0B 00 00 00 DC 03 40 00 00 00 00 00 12 00 00 00  ......@.........
00000220: 16 00 00 00 C0 03 40 00 00 00 00 00 12 00 00 00  ......@.........
00000230: 10 00 00 00 30 04 40 00 00 00 00 00 12 00 00 00  ....0.@.........
00000240: 1D 00 00 00 04 10 41 00 00 00 00 00 10 00 14 00  ......A.........
00000250: 2C 00 00 00 14 04 40 00 00 00 00 00 12 00 00 00  ,.....@.........
00000260: 00 6C 69 62 63 2E 73 6F 2E 36 00 70 75 74 73 00  .libc.so.6.puts.   section ".dynstr" contents
00000270: 61 62 6F 72 74 00 70 72 69 6E 74 66 00 5F 5F 66  abort.printf.__f
00000280: 70 73 63 72 5F 76 61 6C 75 65 73 00 5F 5F 6C 69  pscr_values.__li
00000290: 62 63 5F 73 74 61 72 74 5F 6D 61 69 6E 00 47 4C  bc_start_main.GL
000002A0: 49 42 43 5F 32 2E 32 00 5F 5F 67 6D 6F 6E 5F 73  IBC_2.2.__gmon_s
000002B0: 74 61 72 74 5F 5F 00                             tart__.
...
```

# Dev Notes

Test an individual dissector without stdout capture:
```
python -m finter.pcap ~/repos/lwerdna/filesamples/simple_http_sll2.pcap
```
