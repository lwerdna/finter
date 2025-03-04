#!/bin/bash

# Test finter against a battery of files from the filesamples

# show invocations
set -x

# quit on first error
set -e

FPATH=$HOME/repos/lwerdna/filesamples

./oha.py $FPATH/simple_http.pcap
./oha.py $FPATH/simple_http_sll2.pcap
./oha.py $FPATH/simple_http_tzsp.pcapng
./oha.py $FPATH/200722_tcp_anon.pcapng
./oha.py $FPATH/teardrop.pcap
./oha.py $FPATH/x509_lets_encrypt.cer
./oha.py $FPATH/hello-windows-x86.pe32.exe
./oha.py $FPATH/hello-windows-x64.pe64.exe
./oha.py $FPATH/hello-mono.exe
./oha.py $FPATH/hello-mono-square.exe
./oha.py $FPATH/square-mono.dll
./oha.py h264_annexb $FPATH/lena_annex.h264

#FPATH=$HOME/fdumps/filesamples
#
##./raw.py $FPATH/lena.gif
##./raw.py $FPATH/dacman.col
##./raw.py $FPATH/lena.bmp
##./raw.py $FPATH/lena.png
##./raw.py $FPATH/SuperMarioBros.nes
#./raw.py $FPATH/busybox-armv4l
#./raw.py $FPATH/busybox-armv4tl
#./raw.py $FPATH/busybox-armv5l
#./raw.py $FPATH/busybox-armv7l
#./raw.py $FPATH/busybox-armv6l
#./raw.py $FPATH/busybox-i586
#./raw.py $FPATH/busybox-i486
#./raw.py $FPATH/busybox-i686
#./raw.py $FPATH/busybox-mips
#./raw.py $FPATH/busybox-mips64
#./raw.py $FPATH/busybox-mipsel
#./raw.py $FPATH/busybox-powerpc
#./raw.py $FPATH/busybox-powerpc-440fp
#./raw.py $FPATH/busybox-sh4
#./raw.py $FPATH/busybox-x86_64
#./raw.py $FPATH/nmbd-mipsel.elf
#./raw.py $FPATH/wtf_arch_29a-unknown-x64.elf
#./raw.py $FPATH/shellcode_loader_win.exe
#./raw.py $FPATH/secret.txt.gpg
#./raw.py $FPATH/secret.txt
#./raw.py $FPATH/quake-dos-x86.exe
#./raw.py $FPATH/pic_with_call_dest_relocations
#./raw.py $FPATH/mips_helloworld_condition_elf
#./raw.py $FPATH/helloworld_with_condition_aarch64_elf
#./raw.py $FPATH/hello-linux-x64.elf
#./raw.py $FPATH/hello-linux-ppc32.elf
#./raw.py $FPATH/hello-android-thumb.elf
#./raw.py $FPATH/hello-android-aarch64.elf
#./raw.py $FPATH/elf_x86
#./raw.py $FPATH/elf_x64_wrapped_exit
#./raw.py $FPATH/elf_thumb2_be
#./raw.py $FPATH/elf_mips32_be
#./raw.py $FPATH/elf_29a
#./raw.py $FPATH/elf64_ppc64_be
#./raw.py $FPATH/ctf_macho_ppc_be.bin
#./raw.py $FPATH/classes.dex
#./raw.py $FPATH/bookworm_elf_thumb
#./raw.py $FPATH/PDIPX.COM
#./raw.py $FPATH/MGENVXD.VXD
#./raw.py $FPATH/elephbrain.rar
#./raw.py $FPATH/lena.jpg
#./raw.py $FPATH/lena.jpeg
#./raw.py $FPATH/testfilewrite.dll
#./raw.py $FPATH/test_mbox.exe
#./raw.py $FPATH/test_mbox.dll
#./raw.py $FPATH/pwnd_x86.dll
#./raw.py $FPATH/pwnd_x64.dll
#./raw.py $FPATH/hello-windows-x86.pe32.exe
#./raw.py $FPATH/QtGuiApp1.exe
#./raw.py $FPATH/hello-macos-x64.macho
#./raw.py $FPATH/MSPACMAN.zip
#./raw.py $FPATH/thttpd-2.29.tar.gz
#./raw.py $FPATH/hello_windows_x64.exe
#./raw.py $FPATH/burgertime.col
#./raw.py $FPATH/hello-sh4
#./raw.py $FPATH/punchline.rot13
#./raw.py $FPATH/punchlines.rot13
#./raw.py $FPATH/punchlines2.rot13
#./raw.py $FPATH/punchline2.rot13
#./raw.py $FPATH/hello.exe
#./raw.py $FPATH/hello-linux-ppc64
#./raw.py $FPATH/test2.macho
#./raw.py $FPATH/dacman_colecovision.rom
#./raw.py $FPATH/mame
#./raw.py $FPATH/echoback
#./raw.py $FPATH/macho_mte_at_10000679c
#./raw.py $FPATH/libc-2.32-aarch64.so
#./raw.py $FPATH/sstic_aarch64.ko
#./raw.py $FPATH/conway_raspi4.txt
#./raw.py $FPATH/dyld_apple_arm64e
#./raw.py $FPATH/elf-Linux-ARMv7-ls
#./raw.py $FPATH/ceph-dencoder-arm32-elf
#./raw.py $FPATH/libpthread_x86_64.so.0
#./raw.py $FPATH/libpthread_thumb2eb.so.0
#./raw.py $FPATH/libpthread_thumb2.so.0
#./raw.py $FPATH/libpthread_ppc32.so.0
#./raw.py $FPATH/libpthread_mipsel.so.0
#./raw.py $FPATH/libpthread_mips.so.0
#./raw.py $FPATH/libpthread_i386.so.0
#./raw.py $FPATH/libpthread_armv7eb.so.0
#./raw.py $FPATH/libpthread_armv7.so.0
#./raw.py $FPATH/libpthread_aarch64.so.0
#./raw.py $FPATH/true_or_false.c
#./raw.py $FPATH/true_or_false-macos-x64
#./raw.py $FPATH/libc.so.6
#./raw.py $FPATH/libpthread_x86_64.so.bndb
#./raw.py $FPATH/ntoskrnl.exe
#./raw.py $FPATH/busybox-x86_64.bndb_hlil.txt
#./raw.py $FPATH/busybox-x86_64.bndb_disassembly.txt
#./raw.py $FPATH/busybox-x86_64.bndb_hlil_ssa.txt
#./raw.py $FPATH/hello-linux-x64.elf_disassembly.txt
#./raw.py $FPATH/tests
#./raw.py $FPATH/tests-macos-x64-macho
#./raw.py $FPATH/Makefile
#./raw.py $FPATH/tests.c
#./raw.py $FPATH/libc-2.32-aarch64-2.so
#./raw.py $FPATH/ntdll-aarch64.dll
#./raw.py $FPATH/foo-linux-x64-DWARF.so
#./raw.py $FPATH/Main.class
#./raw.py $FPATH/busybox-arm64
#./raw.py $FPATH/magic_division_armv7.so
#./raw.py $FPATH/libhdk-mips-elf
#./raw.py $FPATH/curl-mips32
#./raw.py $FPATH/mfcr-linux-ppc32.elf
#./raw.py $FPATH/babymips-nanomips
#./raw.py $FPATH/ntoskrnl.bndb
#./raw.py $FPATH/busybox-x86_64.bndb
#./raw.py $FPATH/wpa_cli-mips64.elf
#./raw.py $FPATH/wpa_cli-mips64.elf.zip
#./raw.py $FPATH/switch_linux_ppc_le_32
#./raw.py $FPATH/md5_armv7-android
#./raw.py $FPATH/md5_x64-macos
