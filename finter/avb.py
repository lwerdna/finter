#!/usr/bin/env python

# android verified boot

# links:
# https://android.googlesource.com/platform/external/avb/+/master/libavb/avb_vbmeta_image.h
# https://android.googlesource.com/platform/external/avb/+/master/libavb/avb_crypto.h

import sys
import struct
import binascii
import enum

from .helpers import *

AVB_MAGIC_LEN = 4
AVB_RELEASE_STRING_SIZE = 48

class AvbAlgorithmType(enum.Enum):
    NONE = 0
    SHA256_RSA2048 = 1
    SHA256_RSA4096 = 2
    SHA256_RSA8192 = 3
    SHA512_RSA2048 = 4
    SHA512_RSA4096 = 5
    SHA512_RSA8192 = 6

def AvbVBMetaImageHeader(fp):
    setBigEndian()

    tag(fp, 4, f'magic[{AVB_MAGIC_LEN}]')

    tagUint32(fp, 'required_libavb_version_major')
    tagUint32(fp, 'required_libavb_version_minor')

    tagUint64(fp, 'authentication_data_block_size')
    tagUint64(fp, 'auxiliary_data_block_size')

    tagUint32(fp, 'algorithm_type', lambda x: enum_int_to_name(AvbAlgorithmType, x))

    tagUint64(fp, 'hash_offset')
    tagUint64(fp, 'hash_size')

    tagUint64(fp, 'signature_offset')
    tagUint64(fp, 'signature_size')

    tagUint64(fp, 'public_key_offset')
    tagUint64(fp, 'public_key_size')

    tagUint64(fp, 'public_key_meatadata_offset')
    tagUint64(fp, 'public_key_meatadata_size')

    tagUint64(fp, 'descriptors_offset')
    tagUint64(fp, 'descriptors_size')

    tagUint64(fp, 'rollback_index')

    tagUint32(fp, 'flags')

    tagUint32(fp, 'rollback_index_location')

    tag(fp, AVB_RELEASE_STRING_SIZE, f'release_string[{AVB_RELEASE_STRING_SIZE}]')

    tag(fp, 80, 'reserved[80]')

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    if not peek(fp, 4) == b'AVB0':
        return

    AvbVBMetaImageHeader(fp)
