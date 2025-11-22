#!/usr/bin/env python

# http://soundfile.sapp.org/doc/WaveFormat/

import os
import sys
import struct
import binascii

from . import pe
from .helpers import *

###############################################################################
# "main"
###############################################################################

def tag_subchunk_header(fp):
    tag(fp, 8, 'Subchunk Header', rewind=True)
    tagString(fp, 4, 'Subchunk1ID')
    length = tagUint32(fp, 'Subchunk1Size') # does NOT include the header
    return length

def tag_subchunk_generic(fp):
    length = tag_subchunk_header(fp)
    tag(fp, length, 'Subchunk Data')

def tag_subchunk_fmt(fp):
    assert peek(fp, 4) == b'fmt '
    length = tag_subchunk_header(fp)
    assert length == 16

    tag(fp, length, 'Subchunk Data', rewind=True)
    tagUint16(fp, 'AudioFormat', '(1 means PCM)')
    num_chans = tagUint16(fp, 'NumChannels', lambda x: f'({x:d})')
    tagUint32(fp, 'SampleRate', lambda x: f'({x:d})')
    tagUint32(fp, 'ByteRate', lambda x: f'({x:d})')
    tagUint16(fp, 'BlockAlign')
    bits_per_sample = tagUint16(fp, 'BitsPerSample', lambda x: f'({x:d})')

    return num_chans, bits_per_sample

def tag_subchunk_data(fp, n_channels, bits_per_sample):
    assert peek(fp, 4) == b'data'
    length = tag_subchunk_header(fp)

    assert bits_per_sample % 8 == 0
    bytes_per_sample = bits_per_sample // 8

    sample_num = 1
    while length:
        tag(fp, n_channels * bytes_per_sample, f'sample[{sample_num}]', rewind=True)
        for i in range(1, n_channels+1):
            if bytes_per_sample == 1:
                tagUint8(fp, f'ch_{i}')
            elif bytes_per_sample == 2:
                tagInt16(fp, f'ch_{i}')
            else:
                tag(fp, 1, f'ch_{i}')
        length -= n_channels * bytes_per_sample
        sample_num += 1
        
def analyze(fp):
    base = fp.tell()

    ok = False
    ChunkId = fp.read(4)
    ChunkSize = fp.read(4)
    Format = fp.read(4)
    Subchunk1ID = fp.read(4)

    fp.seek(base)

    if ChunkId != b'RIFF' or Format != b'WAVE' or Subchunk1ID != b'fmt ':
        return

    # parse main "RIFF" chunk descriptor
    tagString(fp, 4, 'ChunkId')
    tagUint32(fp, 'ChunkSize')
    tagString(fp, 4, 'Format')

    # parse subchunks
    while not IsEof(fp):
        subchunk_id = peek(fp, 4)
        if subchunk_id == b'fmt ':
            n_chans, bits_per_sample = tag_subchunk_fmt(fp)
        elif subchunk_id == b'data':
            tag_subchunk_data(fp, n_chans, bits_per_sample)
        else:
            tag_subchunk_generic(fp)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
