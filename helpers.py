#!/usr/bin/env python

import io
import os
import re
import sys
from subprocess import Popen, PIPE

from finter import *
from intervaltree import Interval, IntervalTree

def shellout(cmd):
    process = Popen(cmd, stdout=PIPE, stderr=PIPE)
    (stdout, stderr) = process.communicate()
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    #print('stdout: -%s-' % stdout)
    #print('stderr: -%s-' % stderr)
    process.wait()
    return (stdout, stderr)

#------------------------------------------------------------------------------
# intervaltree stuff
#------------------------------------------------------------------------------

def intervals_from_text(lines):
    """ convert list of "[0 5] blah" lines to intervals """

    intervals = []
    for (i,line) in enumerate(lines):
        #print('line %d: %s' % (i,line))
        if not line:
            continue

        m = re.match(r'\[(.*?),(.*?)\) (.*?) (.*)', line)
        if not m:
            raise Exception('MALFORMED: %s' % line)

        # Interval .begin .end .type .comment
        begin = int(m.group(1), 16)
        end = int(m.group(2), 16)
        type_ = m.group(3)
        comment = m.group(4)

        ibaggage = (type_, comment)

        i = Interval(begin, end, ibaggage)
        intervals.append(i)

    return intervals

# minimum idea of "node"
class FinterNode():
    def __init__(self, begin, end, type_, comment):
        self.begin = begin
        self.end = end
        self.type_ = type_
        self.comment = comment
        self.children = []
        self.parent = None

    def __str__(self, depth=0):
        result = '  '*depth+'FinterNode'
        result += '[%d, %d)\n' % (self.begin, self.end)
        for c in sorted(self.children, key=lambda x: x.begin):
            result += c.__str__(depth+1)
        return result

def sort_and_create_fragments(node, NodeClass=FinterNode):
    result = []

    if not node.children:
        return

    # fill gaps ahead of each child
    current = node.begin
    for child in sorted(node.children, key=lambda ch: ch.begin):
        if current < child.begin:
            frag = NodeClass(current, child.begin, 'raw', 'fragment')
            frag.parent = node
            result.append(frag)
        result.append(child)
        current = child.end

    # fill possible gap after last child
    if current != node.end:
        frag = NodeClass(current, node.end, 'raw', 'fragment')
        frag.parent = node
        result.append(frag)

    # replace children with list that includes gaps
    node.children = result

    # recur on children
    for child in node.children:
        sort_and_create_fragments(child, NodeClass)

def interval_tree_to_hierarchy(tree, NodeClass=FinterNode):
    """ convert IntervalTree to a hierarchy """

    # initialize interval -> node mapping
    child2parent = {i:None for i in tree}

    # consider every interval a possible parent
    for parent in tree:
        # whatever intervals they envelop are their possible children
        children = tree.envelop(parent)
        children = list(filter(lambda c: c.length() != parent.length(), children))
        for c in children:
            # children without a parent are adopted immediate
            if not child2parent[c]:
                child2parent[c] = parent
            # else children select their smallest parents
            else:
                child2parent[c] = min(child2parent[c], parent, key=lambda x: x.length())

    # wrap the child2parent relationships
    hnRoot = NodeClass(tree.begin(), tree.end(), 'none', 'root')
    interval_to_node = { i:NodeClass(i.begin, i.end, i.data[0], i.data[1]) for i in tree }

    for (child, parent) in child2parent.items():
        hnChild = interval_to_node[child]
        if not parent:
            hnChild.parent = hnRoot
            hnRoot.children.append(hnChild)
        else:
            hnParent = interval_to_node[parent]
            hnChild.parent = hnParent
            hnParent.children.append(hnChild)

    # create fragments
    sort_and_create_fragments(hnRoot, NodeClass)

    # done
    return hnRoot

#------------------------------------------------------------------------------
# convenience stuff
#------------------------------------------------------------------------------

def find_dissector(fpath):
    """ given a file path, return a dissector function """

    # first try if `file` will help us
    sig2dissector = [
        (r'GPG symmetrically encrypted data', gpg.analyze),
        (r'ELF 32-bit (LSB|MSB)', elf32.analyze),
        (r'ELF 64-bit (LSB|MSB)', elf64.analyze),
        (r'PE32 executable .* 80386', pe32.analyze),
        (r'PE32\+ executable .* x86-64', pe64.analyze),
        (r'Dalvik dex file', dex.analyze),
        (r'MS-DOS executable', exe.analyze),
        (r'Mach-O ', macho.analyze),
        (r'RIFF \(little-endian\) data, WAVE audio', wav.analyze),
        (r'^COMBO_BOOT', combo_boot.analyze)
    ]

    (file_str, _) = shellout(['file', fpath])
    analyze = None
    for (sig, dissector) in sig2dissector:
        if re.search(sig, file_str):
            #print('matched on %s' % sig)
            analyze = dissector
            break

    # next see if a file sample might help us
    sample = open(fpath, 'rb').read(32)
    if sample.startswith(b'COMBO_BOOT\x00\x00'):
        analyze = combo_boot.analyze
    if sample.startswith(b'AVB0'):
        analyze = avb.analyze

    # next guess based on file name or extension
    if not analyze:
        if fpath.endswith('.rel'):
            if re.match(r'[XDQ][HL][234]\x0a', sample.decode('utf-8')):
                analyze = rel.analyze
        elif fpath.endswith('.ihx'):
            analyze = ihx.analyze
        elif fpath.endswith('.mkv'):
            analyze = mkv.analyze

    return analyze

def dissect_file(fpath, populate_fragments=True):
    """ identify file path, call dissector """

    analyze = find_dissector(fpath)
    if not analyze:
        return

    fsize = os.path.getsize(fpath)

    # capture stdout to StringIO
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf

    # call analyzer
    lines = ''
    with open(fpath, 'rb') as fp:
        analyze(fp)
        lines = buf.getvalue()

    # uncapture stdout
    buf.close()
    sys.stdout = old_stdout

    # lines to intervals
    lines = lines.split('\n')
    intervals = intervals_from_text(lines)

    return IntervalTree(intervals)

def finter_type_to_struct_fmt(type_):
    # currently they're 1:1
    assert type_ in {'B', '<B', '>B', 'H', '<H', '>H', 'W', '<W', '>W', 'I', '<I', '>I', 'Q', '<Q', '>Q'}
    return type_
