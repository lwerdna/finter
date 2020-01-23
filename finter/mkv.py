#!/usr/bin/env python

import sys
import ebmlite

from .elf import *
from .helpers import *

def pprint(el, values=True, out=sys.stdout, depth=0):
    if isinstance(el, ebmlite.core.Document):
        if el.size and depth < 3:
            print("[0x%X,0x%X) %s (Document, type %s)\n" % (el.offset, el.offset + el.size, str(el.name), el.type))
        for i in el:
            pprint(i, values, out, depth+1)
    else:
        if el.size and depth < 3:
            print("[0x%X,0x%X) %s (ID: 0x%0X)" % (el.offset, el.offset + el.size, str(el.name), el.id))
        if isinstance(el, ebmlite.core.MasterElement):
            #print(": (master) %d subelements\n" % len(el.value))
            for i in el:
                pprint(i, values, out, depth+1)
        else:
            #print(": (%s)" % el.dtype.__name__)
            #if values and not isinstance(el, ebmlite.core.BinaryElement):
            #    print(" %r\n" % (el.value))
            #else:
            #    print("\n")
            pass

def analyze(fp):
    if not fp.read(4) == b'\x1A\x45\xDF\xA3':
        return

    fp.seek(0)
    schema = ebmlite.loadSchema('matroska.xml')
    doc = schema.load(fp)
    pprint(doc)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
