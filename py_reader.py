#!/usr/bin/env python3
#
# dump a given file as python code that would read the same from the file

import re
import sys
import struct
import binascii

from helpers import dissect_file, intervals_from_text, intervals_to_tree, FinterNode, finter_type_to_struct_fmt

class MyNode(FinterNode):
    def __init__(self, begin, end, type_, comment):
        super().__init__(begin, end, type_, comment)
        self.name = re.split('[^0-9a-zA-Z_]', self.comment)[0]

        # needed
        self.fp = None

    def set_fp(self, fp):
        self.fp = fp
        for child in self.children:
            child.set_fp(fp)

    def go(self, comma=False, depth=0):
        indent = '    '*depth

        # if we have child children, do not emit our "value" (the bytes we tag)
        # instead, return a dict with named children
        if self.children:
            # get the requested names of each child
            names = [ch.name for ch in self.children]

            # resolve conflicts by appending a numeric distinguisher
            suffix = {}
            for ch in self.children:
                name = ch.name
                if names.count(name) > 1:
                    if name in suffix:
                        ch.name = f'{ch.name}{suffix[ch.name]}'
                        suffix[name] += 1
                    else:
                        ch.name = f'{ch.name}0'
                        suffix[name] = 1

            # print recursively
            print(f'{indent}\'{self.name}\': ' + '{')
            for i,ch in enumerate(self.children):
                last = (i == len(self.children)-1)
                ch.go(not last, depth+1)
            print(f'{indent}' + '}' + (',' if comma else ''))

        # we have no children: emit code to read ourselves from file pointer
        else:
            self.fp.seek(self.begin)
            data = self.fp.read(self.end - self.begin)
            extra = ',' if comma else ''

            match self.type_:
                case 'none': print(f'{indent}\'{self.name}\' = null' + extra)
                case 'raw':
                    print(f'{indent}\'{self.name}\': slurp(0x{self.begin:X}, 0x{self.end:X}, \'raw\'){extra}')
                case _:
                    fmt = finter_type_to_struct_fmt(self.type_)
                    print(f'{indent}\'{self.name}\': slurp(0x{self.begin:X}, 0x{self.end:X}, \'{fmt}\'){extra}')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('ERROR: missing file parameter')
        print('usage: %s <file>' % sys.argv[0])
        sys.exit(-1)

    fpath = sys.argv[1]

    interval_tree = dissect_file(fpath)

    root = intervals_to_tree(interval_tree, MyNode)

    sorted_children = sorted(root.children, key=lambda x: x.begin)

    # debug?
    if 0:
        graph(root)
        sys.exit(-1)

    print('''
def read(fp):
    def slurp(begin, end, fmt):
        fp.seek(begin)
        data = fp.read(end-begin)
        match fmt:
            case 'raw': return data
            case 'none': return None
            case _: return struct.unpack(fmt, data)[0]
''')

    with open(sys.argv[1], 'rb') as fp:
        root.set_fp(fp)

        print('    return {')
        for i,ch in enumerate(root.children):
            last = i == len(root.children)-1
            ch.go(not last, 2)
        print('    }')
