#!/usr/bin/env python

import re
import io
import sys
from finter import elf32, elf64

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as fp:
        elf32.analyze(fp)
        elf64.analyze(fp)

