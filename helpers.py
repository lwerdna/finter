#!/usr/bin/env python

import io
import os
import re
import sys
from subprocess import Popen, PIPE

from finter import *
import algorithm

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
# interval stuff
#------------------------------------------------------------------------------

class Interval:
    def __init__(self, begin, end, type_, comment):
        self.begin, self.end = begin, end
        self.type_ = type_
        self.comment = comment

    def __len__(self):
        return self.end - self.begin

def intervals_from_text(lines):
    """ convert list of "[0 5] blah" lines to intervals """

    lo_bound, hi_bound = None, None

    intervals = []
    for i,line in enumerate(lines):
        #print('line %d: %s' % (i,line))
        if not line:
            continue

        # comments
        if line.startswith('//') or line.startswith('#'):
            continue

        # eg: [0x16F,0x171) >H HeaderChecksum=0xE949
        m = re.match(r'\[(.*?),(.*?)\) (.*?) (.*)', line)
        if not m:
            raise Exception('MALFORMED: %s' % line)

        # Interval .begin .end .type .comment
        begin = int(m.group(1), 16)
        end = int(m.group(2), 16)
        type_ = m.group(3)
        comment = m.group(4)

        intervals.append(Interval(begin, end, type_, comment))

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

    def __len__(self):
        return self.end - self.begin

    def __str__(self, depth=0):
        result = '  '*depth
        result += '[0x%x,0x%x) %s %s\n' % (self.begin, self.end, self.type_, self.comment)
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

def intervals_to_tree_worker(anode, NodeClass):
    if anode.root:
        result = NodeClass(0, 0, '', 'root')
    else:
        interval = anode.item
        result = NodeClass(interval.begin, interval.end, interval.type_, interval.comment)
    
    result.children = [intervals_to_tree_worker(c, NodeClass) for c in anode.children]

    return result

def intervals_to_tree(intervals, NodeClass=FinterNode):
    # define relation R: (x,y) \in R iff x envelopes y
    def relation(x:Interval, y:Interval):
        return x.begin <= y.begin and x.end >= y.end

    atree = algorithm.build(intervals, relation, None)

    # the whole-file interval should have been placed just below root
    assert len(atree.children) == 1
    atree = atree.children[0]

    # convert the algorithm's output (anodes with .item holding Interval) to
    # the requested NodeClass

    hnRoot = intervals_to_tree_worker(atree, NodeClass)

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
        (r'pcapng capture file', pcapng.analyze),
        (r'pcap capture file', pcap.analyze)
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
    intervals = [i for i in intervals if i.end > i.begin]

    # add interval for whole file if there isn't one already
    fsize = os.path.getsize(fpath)
    if not [i for i in intervals if i.end-i.begin == fsize]:
        intervals.append(Interval(0, fsize, 'raw', 'file'))

    return intervals

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
