#!/usr/bin/env python

import os
import sys
import struct
import binascii

from . import pe
from .helpers import *

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    if not (pe.idFile(fp) == "pe64"):
        #print 'pe.idFile(fp) == ' + pe.idFile(fp)
        return

    image_dos_header = pe.tag_image_dos_header(fp)

    fp.seek(image_dos_header['e_lfanew'])

    image_nt_headers_offs = fp.tell()
    image_nt_headers = pe.tag_image_nt_headers(fp, 64)

    image_file_header = image_nt_headers['image_file_header']

    (oScnReloc, nScnReloc) = (None,None)

    o_sections = image_nt_headers['image_optional_header_offs'] + image_file_header['SizeOfOptionalHeader']
    fp.seek(o_sections)

    for i in range(image_file_header['NumberOfSections']):
        section = pe.tag_section(fp, 64)

        name, o, n = section['Name'], section['PointerToRawData'], section['SizeOfRawData']

        if name == '.reloc':
            fp.seek(o)
            pe.tagReloc(fp, n)
        elif name == 'pdata':
            fp.seek(o)
            pe.tagPdata(fp, n)
        else:
            print("[0x%X,0x%X) section \"%s\" contents" % (o, o+n, name))

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
