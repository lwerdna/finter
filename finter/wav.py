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

def analyze(fp):
	if fp.read(4) != b'RIFF': return
	length = uint32(fp);
	if fp.read(4) != b'WAVE': return
	if fp.read(4) != b'fmt ': return

	fp.seek(0)
	tagString(fp, 4, 'RIFF chunk tag')
	tagUint32(fp, 'RIFF chunk length')
	tagString(fp, 4, 'type')

	tag(fp, length, 'RIFF subchunks')

	fp.seek(12)

	# fmt
	(_, chunk_sz) = (uint32(fp), uint32(fp))
	rewind(fp, 8)
	tag(fp, 8+chunk_sz, 'fmt chunk', 1)
	assert chunk_sz == 16, "can't handle abnormal chunk size: %d"%chunk_sz
	tagString(fp, 4, 'tag')
	tagUint32(fp, 'size')
	tagUint16(fp, 'audio format')
	num_chans = tagUint16(fp, 'num channels')
	tagUint32(fp, 'sample rate')
	tagUint32(fp, 'byte rate')
	tagUint16(fp, 'block align')
	bits_per_sample = tagUint16(fp, 'bits per sample')

	# data
	(_, chunk_sz) = (uint32(fp), uint32(fp))
	rewind(fp, 8)
	tag(fp, 8+chunk_sz, 'data')
	tagString(fp, 4, 'tag')
	tagUint32(fp, 'size')


	assert bits_per_sample in [8, 16, 32], "can't handle abnormal bits per sample: %d"%bits_per_sample
	bytes_per_sample = bits_per_sample // 8
	bytes_per_channel = bytes_per_sample // num_chans

	assert chunk_sz % bytes_per_sample == 0, "chunk size doesn't align with sample data"
	num_samples = chunk_sz // bytes_per_sample
	for sample_idx in range(num_samples):
		tag(fp, bytes_per_sample*num_chans, 'sample %d' % sample_idx, 1)
		for ch in range(num_chans):
			tag(fp, bytes_per_channel, 'channel %d' % ch)

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fp:
        analyze(fp)
