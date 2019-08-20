#!/usr/bin/env python

import io
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

def dissect_file(fpath):
    """ identify file path, call dissector """

    sig2dissector = [
        ('GPG symmetrically encrypted data', gpg.analyze),
        ('ELF 32-bit LSB executable', elf32.analyze),
        ('ELF 32-bit MSB executable', elf32.analyze),
        ('ELF 64-bit LSB executable', elf64.analyze),
        ('ELF 64-bit MSB executable', elf64.analyze),
    ]

    (file_str, _) = shellout(['file', fpath])
    analyze = None
    for (sig, dissector) in sig2dissector:
        if sig in file_str:
            #print('matched on %s' % sig)
            analyze = dissector
            break

    if not analyze:
        return

    # capture stdout to StringIO
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf

    # call analyzer 
    interval_lines = ''
    with open(fpath, 'rb') as fp:
        analyze(fp)
        interval_lines = buf.getvalue()

    # cleanup, return
    buf.close()
    sys.stdout = old_stdout
    return interval_lines.split('\n')

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

def interval_tree_to_hierarchy(tree, nodeType=hnode):
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
    hnRoot = nodeType(Interval(tree.begin(), tree.end(), "root"))
    inter2node = { x:nodeType(x) for x in tree }

    for (child, parent) in child2parent.items():
        hnChild = inter2node[child]
        if not parent:
            hnRoot.children.append(hnChild)
        else:
            hnParent = inter2node[parent]
            hnParent.children.append(hnChild)

    # done
    return hnRoot