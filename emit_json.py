#!/usr/bin/env python3
#
# dump a given file's tagging as json

import re
import sys
import json
import struct
import binascii

from helpers import dissect_file, intervals_from_text, interval_tree_to_hierarchy, FinterNode

# we'll augment the default node type with the ability to produce a python
# data structure serializable to json
class JsonNode(FinterNode):
    def __init__(self, begin, end, type_, comment):
        super().__init__(begin, end, type_, comment)

        # generate a name based on our comment, eg:
        # comment                                      name
        # -------                                      ----
        # "public_key_size=0x408"                      "public_key_size"
        # "tag=0x4 AVB_DESCRIPTOR_TAG_CHAIN_PARTITION" "tag"
        # "data[1128]"                                 "data"
        self.name = re.split('[^a-zA-Z_]', self.comment)[0]        

        # needed
        self.fp = None

    def set_fp(self, fp):
        self.fp = fp
        for child in self.children:
            child.set_fp(fp)

    def data_structify(self):
        # if we have child children, do not emit our "value" (the bytes we tag)
        # instead, return a dict with named children
        if self.children:
            # get the requested names of each child
            names = [ch.name for ch in self.children]

            #if 'descriptor' in names:
            #    breakpoint()

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
            
            # make the data structure recursively
            return { ch.name : ch.data_structify() for ch in self.children }
                
        # we have no children: emit our tagged bytes in serialized form
        else:
            self.fp.seek(self.begin)
            data = self.fp.read(self.end - self.begin)

            match self.type_:
                # this could be made much simpler and less literal, but the
                # current type strings just _happen_ to be chosen from the
                # python format strings (but might not always be)
                case '<B': return struct.unpack('<B', data)[0] # unsigned u8
                case '<b': return struct.unpack('<b', data)[0] # signed int8
                case '>B': return struct.unpack('>B', data)[0]
                case '>b': return struct.unpack('>b', data)[0]

                case '<H': return struct.unpack('<H', data)[0] # unsigned u16
                case '<h': return struct.unpack('<h', data)[0] # signed int16
                case '>H': return struct.unpack('>H', data)[0]
                case '>h': return struct.unpack('>h', data)[0]

                case '<I': return struct.unpack('<I', data)[0] # unsigned u32
                case '<i': return struct.unpack('<i', data)[0] # signed int32
                case '>I': return struct.unpack('>I', data)[0]
                case '>i': return struct.unpack('>i', data)[0]

                case '<Q': return struct.unpack('<Q', data)[0] # unsigned u64
                case '<q': return struct.unpack('<q', data)[0] # signed int64
                case '>Q': return struct.unpack('>q', data)[0]
                case '>q': return struct.unpack('>q', data)[0]

                case 'raw': return binascii.hexlify(data).decode('utf-8')
                case 'none': return 'null'
                case _: breakpoint()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('ERROR: missing file parameter')
        print('usage: %s <file>' % sys.argv[0])
        sys.exit(-1)

    fpath = sys.argv[1]

    interval_tree = dissect_file(fpath)

    root = interval_tree_to_hierarchy(interval_tree, JsonNode)

    sorted_children = sorted(root.children, key=lambda x: x.begin)

    # debug?
    if 0:
        graph(root)
        sys.exit(-1)

    with open(sys.argv[1], 'rb') as fp:
        root.set_fp(fp)
        ds = root.data_structify()
        print(json.dumps(ds, indent=4))
