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
AVB_VBMETA_IMAGE_HEADER_SIZE = 256

class AvbAlgorithmType(enum.Enum):
    NONE = 0
    SHA256_RSA2048 = 1
    SHA256_RSA4096 = 2
    SHA256_RSA8192 = 3
    SHA512_RSA2048 = 4
    SHA512_RSA4096 = 5
    SHA512_RSA8192 = 6

class AvbDescriptorTag(enum.Enum):
    AVB_DESCRIPTOR_TAG_PROPERTY = 0
    AVB_DESCRIPTOR_TAG_HASHTREE = 1
    AVB_DESCRIPTOR_TAG_HASH = 2
    AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE = 3
    AVB_DESCRIPTOR_TAG_CHAIN_PARTITION = 4

class AvbVBMetaImageFlags(enum.Enum):
    AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED = 1
    AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED = 2

def AvbVBMetaImageHeader(fp):
    setBigEndian()

    mark = fp.tell()

    tag(fp, 4, f'magic[{AVB_MAGIC_LEN}]')

    tagUint32(fp, 'required_libavb_version_major')
    tagUint32(fp, 'required_libavb_version_minor')

    authentication_data_block_size = tagUint64(fp, 'authentication_data_block_size')
    auxiliary_data_block_size = tagUint64(fp, 'auxiliary_data_block_size')

    tagUint32(fp, 'algorithm_type', lambda x: enum_int_to_name(AvbAlgorithmType, x))

    hash_offset = tagUint64(fp, 'hash_offset')
    hash_size = tagUint64(fp, 'hash_size')

    signature_offset = tagUint64(fp, 'signature_offset')
    signature_size = tagUint64(fp, 'signature_size')

    public_key_offset = tagUint64(fp, 'public_key_offset')
    public_key_size = tagUint64(fp, 'public_key_size')

    tagUint64(fp, 'public_key_metadata_offset')
    tagUint64(fp, 'public_key_metadata_size')

    descriptors_offset = tagUint64(fp, 'descriptors_offset')
    descriptors_size = tagUint64(fp, 'descriptors_size')

    tagUint64(fp, 'rollback_index')

    tagUint32(fp, 'flags', lambda x: flags_string(AvbVBMetaImageFlags, x))

    tagUint32(fp, 'rollback_index_location')

    tag(fp, AVB_RELEASE_STRING_SIZE, f'release_string[{AVB_RELEASE_STRING_SIZE}]')

    tag(fp, 80, 'reserved[80]')

    assert fp.tell() - mark == AVB_VBMETA_IMAGE_HEADER_SIZE

    fp.seek(mark)
    tag(fp, AVB_VBMETA_IMAGE_HEADER_SIZE, 'AvbVBMetaImageHeader')

    return {
        'authentication_data_block_size': authentication_data_block_size,
        'auxiliary_data_block_size': auxiliary_data_block_size,
        'public_key_offset': public_key_offset,
        'public_key_size': public_key_size,
        'hash_offset': hash_offset,
        'hash_size': hash_size,
        'signature_offset': signature_offset,
        'signature_size': signature_size,
        'descriptors_offset': descriptors_offset,
        'descriptors_size': descriptors_size
    }

# * The "Authentication data" block is |authentication_data_block_size|
# * bytes long and contains the hash and signature used to authenticate
# * the vbmeta image. The type of the hash and signature is defined by
# * the |algorithm_type| field.
def AuthenticationData(fp, hdr):
    mark = fp.tell()

    fp.seek(mark + hdr['hash_offset'])
    tag(fp, hdr['hash_size'], 'hash')

    fp.seek(mark + hdr['signature_offset'])
    tag(fp, hdr['signature_size'], 'signature')

    fp.seek(mark)
    tag(fp, hdr['authentication_data_block_size'], 'Authentication Data')

# * The "Auxiliary data" is |auxiliary_data_block_size| bytes long and
# * contains the auxiliary data including the public key used to make
# * the signature and descriptors.
def AuxiliaryData(fp, hdr):
    mark = fp.tell()

    # parse the descriptors
    descrs_length = hdr['descriptors_size']
    descrs_start = mark + hdr['descriptors_offset']
    fp.seek(descrs_start)
    while fp.tell() - descrs_start < descrs_length:
        avb_descriptor(fp)

    # parse the public key
    fp.seek(mark + hdr['public_key_offset'])
    AvbRSAPublicKey(fp)

    fp.seek(mark)
    tag(fp, hdr['auxiliary_data_block_size'], 'Auxiliary Data')

def AvbRSAPublicKeyHeader(fp):
    mark = fp.tell()

    key_num_bits = tagUint32(fp, 'key_num_bits')
    n0inv = tagUint32(fp, 'n0inv')

    fp.seek(mark)
    tag(fp, 8, 'AvbRSAPublicKeyHeader')

    return {
        'key_num_bits': key_num_bits,
        'n0inv': n0inv
    }

def AvbRSAPublicKey(fp):
    mark = fp.tell()

    #breakpoint()
    hdr = AvbRSAPublicKeyHeader(fp)

    n_length = hdr['key_num_bits']//8
    tag(fp, n_length, 'n')
    tag(fp, n_length, 'rr')

    fp.seek(mark)
    tag(fp, 8 + 2*n_length, 'AvbRSAPublicKey')

def AvbDescriptor(fp):
    mark = fp.tell()

    tag_ = tagUint64(fp, 'tag', lambda x: enum_int_to_name(AvbDescriptorTag, x))
    num_bytes_following = tagUint64(fp, 'num_bytes_following')

    fp.seek(mark)
    tag(fp, 2*8, 'AvbDescriptor')

    return {
        'tag': tag_,
        'num_bytes_following': num_bytes_following
    }

def avb_descriptor(fp):
    mark = fp.tell()

    info = AvbDescriptor(fp)

    tag(fp, info['num_bytes_following'], f'data[{info["num_bytes_following"]}]')

    fp.seek(mark)
    tag(fp, 2*8 + info['num_bytes_following'], 'descriptor')

###############################################################################
# "main"
###############################################################################

def analyze(fp):
    if not peek(fp, 4) == b'AVB0':
        return

    hdr = AvbVBMetaImageHeader(fp)

    o_auth = fp.tell()
    AuthenticationData(fp, hdr)

    o_aux = fp.tell()
    AuxiliaryData(fp, hdr)
