#!/usr/bin/env python3
#
# dump a given file's tagging as json

import re
import sys
import json
import struct
import binascii

from helpers import dissect_file, intervals_from_text, intervals_to_tree, FinterNode, finter_type_to_struct_fmt, handle_argv_common_utility

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
        self.name = re.split('[^a-zA-Z0-9_]', self.comment)[0]

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
                case 'raw': return binascii.hexlify(data).decode('utf-8')
                case 'none': return 'null'
                case _:
                    fmt = finter_type_to_struct_fmt(self.type_)
                    return struct.unpack(fmt, data)[0]


if __name__ == '__main__':
    dissector, fpath, offset = handle_argv_common_utility()

    intervals = dissect_file(fpath, offset, dissector)

    root = intervals_to_tree(intervals, JsonNode)

    sorted_children = sorted(root.children, key=lambda x: x.begin)

    # debug?
    if 0:
        graph(root)
        sys.exit(-1)

    breakpoint()

    with open(fpath, 'rb') as fp:
        root.set_fp(fp)

        ds = root.data_structify()
        print(json.dumps(ds, indent=4))
