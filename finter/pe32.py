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

    image_dos_header = pe.tag_image_dos_header(fp)

    fp.seek(image_dos_header['e_lfanew'])

    image_nt_headers_offs = fp.tell()
    image_nt_headers = pe.tag_image_nt_headers(fp, 32)

    image_file_header = image_nt_headers['image_file_header']

    (oScnReloc, nScnReloc) = (None,None)

    o_sections = image_nt_headers['image_optional_header_offs'] + image_file_header['SizeOfOptionalHeader']
    fp.seek(o_sections)

    scnhdrs = pe.tag_section_headers(fp, image_file_header['NumberOfSections'])

    for hdr in scnhdrs:
        name, o, n = hdr['Name'], hdr['PointerToRawData'], hdr['SizeOfRawData']

        if name == '.reloc':
            fp.seek(o)
            pe.tagReloc(fp, n)
        else:
            print("[0x%X,0x%X) section \"%s\" contents" % (o, o+n, name))

    # If data directory entry 14 (COM_DESCRIPTOR) looks like it points to a ClrHeader/IMAGE_COR20_HEADER
    # this is a .NET executable.
    dde = image_nt_headers['image_optional_header']['data_directory'][14]
    rva = dde['VirtualAddress']
    if rva and dde['Size'] == 72:
        # resolve virtual address to offset
        if offs := pe.rva_to_file_offset(rva, scnhdrs):
            fp.seek(offs)
            pe.tag_image_cor20_header(fp)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
