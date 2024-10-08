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

def find_dissector(fpath, offset=0, failure_actions=[]):
    """ given a file path, return a dissector function """

    # TECHNIQUE 1: match on output of `file`
    #
    sig2analyze = [
        (r'GPG symmetrically encrypted data', gpg.analyze),
        (r'ELF 32-bit (LSB|MSB)', elf32.analyze),
        (r'ELF 64-bit (LSB|MSB)', elf64.analyze),
        (r'PE32 executable .* 80386', pe32.analyze),
        (r'PE32\+ executable .* x86-64', pe64.analyze),
        (r'Dalvik dex file', dex.analyze),
        (r'MS-DOS executable', exe.analyze),
        (r'Mach-O ', macho.analyze),
        (r'RIFF \(little-endian\) data, WAVE audio', wav.analyze),
        (r'^COMBO_BOOT', combo_boot.analyze),
        (r'u-boot legacy uImage', uboot.analyze),
        (r'pcapng capture file', pcapng.analyze)
    ]

    (file_str, _) = shellout(['file', fpath])
    analyze = None
    for (sig, dissector) in sig2analyze:
        if re.search(sig, file_str):
            #print('matched on %s' % sig)
            analyze = dissector
            break

    # TECHNIQUE 2: sample some bytes from the file
    #
    if not analyze:
        with open(fpath, 'rb') as fp:
            fp.seek(offset)
            sample = fp.read(32)

        if sample.startswith(b'COMBO_BOOT\x00\x00'):
            analyze = combo_boot.analyze
        if sample.startswith(b'AVB0'):
            analyze = avb.analyze
        if sample[4:8] == b'\x01\x00\x41\x54':
            analyze = atags.analyze

    # TECHNIQUE 3: guess based on file extension
    #
    if not analyze:
        if fpath.endswith('.rel'):
            if re.match(r'[XDQ][HL][234]\x0a', sample.decode('utf-8')):
                analyze = rel.analyze
        elif fpath.endswith('.ihx'):
            analyze = ihx.analyze
        elif fpath.endswith('.mkv'):
            analyze = mkv.analyze
        elif fpath.endswith('.pcapng'):
            analyze = pcapng.analyze

    if not analyze:
        if 'print' in failure_actions:
            print(f'ERROR: unable to infer analyze function for "{fpath}"', file=sys.stderr)
        if 'exit' in failure_actions:
            sys.exit(-1)

    return analyze

# 'pe32' -> finter.pe32.analyze
def lookup_analyze_function(dissector_name, failure_actions=[]):
    if module := sys.modules.get('finter.' + dissector_name):
        return module.analyze

    if 'print' in failure_actions:
        print(f'ERROR: unable to locate dissector module "{dissector_name}"', file=sys.stderr)
    if 'exit' in failure_actions:
        sys.exit(-1)

def dissect_file(fpath, initial_offset=0, dissector_name=''):
    """ identify file, call dissector """

    # find analyze function
    analyze = None

    # if user says analyze with "pe32", try to get module 'finter.pe32' .analyze
    if dissector_name:
        if (analyze := lookup_analyze_function(dissector_name, ['print'])) is None:
            return

    # else try to infer dissector from file
    if not analyze:
        analyze = find_dissector(fpath, initial_offset)

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
        fp.seek(initial_offset)
        analyze(fp)
        lines = buf.getvalue()

    # uncapture stdout
    buf.close()
    sys.stdout = old_stdout

    # lines to intervals
    lines = lines.split('\n')
    intervals = intervals_from_text(lines)

    # filter out null intervals
    intervals = [i for i in intervals if i.length()]

    return IntervalTree(intervals)

def finter_type_to_struct_fmt(type_):
    # currently they're 1:1
    assert type_ in {'B', '<B', '>B', 'H', '<H', '>H', 'W', '<W', '>W', 'I', '<I', '>I', 'Q', '<Q', '>Q'}
    return type_

def handle_argv_common_utility():
    dissector, fpath, offset = None, None, 0

    if len(sys.argv) < 2:
        print('ERROR: missing file parameter')
        print('usage:')
        print('    %s [dissector] <file> [offset]' % sys.argv[0])
        print('')
        print('where offset is given in hex')
    else:
        if len(sys.argv)-1 == 1:
            # ./finter file.bin
            fpath = sys.argv[1]
        elif len(sys.argv)-1 == 2:
            # ./finter file.bin 0x10
            if os.path.isfile(sys.argv[1]):
                fpath = sys.argv[1]
                offset = int(sys.argv[2], 16)
            # ./finter pe32 file.bin
            else:
                if os.path.isfile(sys.argv[2]):
                    dissector = sys.argv[1]
                    fpath = sys.argv[2]
        else:
            # ./finter pe32.bin file.bin 0x10
            dissector = sys.argv[1]
            fpath = sys.argv[2]
            dissector = sys.argv[3]

    return dissector, fpath, offset
