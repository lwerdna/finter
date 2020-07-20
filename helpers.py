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

        m = re.match(r'\[(.*?),(.*?)\) (.*)', line)
        if not m:
            raise Exception('MALFORMED: %s' % line)

        # Interval .begin .end .data
        i = Interval(int(m.group(1),16), int(m.group(2),16), m.group(3))
        intervals.append(i)

    return intervals

def interval_fragments(start, end, intervals):
    """ given [start,end) and intervals, return list of unclaimed intervals """
    frag_tree = IntervalTree()
    frag_tree.add(Interval(start, end, 'fragment'))
    for i in intervals:
        frag_tree.chop(i.begin, i.end)
    return list(frag_tree)

class hnode():
    def __init__(self, interval):
        self.interval = interval
        self.children = []
    def __str__(self, depth=0):
        result = '  '*depth+'hnode'
        result += str(self.interval) + '\n'
        for c in sorted(self.children, key=lambda x: x.interval.begin):
            result += c.__str__(depth+1)
        return result

def interval_tree_to_hierarchy(tree, NodeClass=hnode):
    """ convert IntervalTree to a hierarchy using hnode """

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

    # wrap the child2parent relationships into hnode
    hnRoot = NodeClass(Interval(tree.begin(), tree.end(), "root"))
    inter2node = { x:NodeClass(x) for x in tree }

    for (child, parent) in child2parent.items():
        hnChild = inter2node[child]
        if not parent:
            hnRoot.children.append(hnChild)
        else:
            hnParent = inter2node[parent]
            hnParent.children.append(hnChild)

    # done
    return hnRoot

#------------------------------------------------------------------------------
# convenience stuff
#------------------------------------------------------------------------------

def find_dissector(fpath):
    """ given a file path, return a dissector function """

    # first try if file will help us
    sig2dissector = [
        (r'GPG symmetrically encrypted data', gpg.analyze),
        (r'ELF 32-bit (LSB|MSB)( pie)? (executable|relocatable)', elf32.analyze),
        (r'ELF 64-bit (LSB|MSB) (executable|relocatable)', elf64.analyze),
        (r'PE32 executable .* 80386', pe32.analyze),
        (r'PE32\+ executable .* x86-64', pe64.analyze),
        (r'Dalvik dex file', dex.analyze),
        (r'MS-DOS executable', exe.analyze),
        (r'Mach-O ', macho.analyze),
        (r'RIFF \(little-endian\) data, WAVE audio', wav.analyze)
    ]

    (file_str, _) = shellout(['file', fpath])
    analyze = None
    for (sig, dissector) in sig2dissector:
        if re.search(sig, file_str):
            #print('matched on %s' % sig)
            analyze = dissector
            break

    if not analyze:
        if fpath.endswith('.rel'):
            with open(fpath, 'rb') as fp:
                if re.match(r'[XDQ][HL][234]\x0a', fp.read(4).decode('utf-8')):
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

    fragments = []
    if populate_fragments:
        fragments = interval_fragments(0, fsize, intervals)

    return IntervalTree(intervals + fragments)    
