#!/usr/bin/env python

from enum import Enum, auto, unique
from .helpers import *

class DWARF_CHILD(Enum):
    DW_CHILDREN_no = 0
    DW_CHILDREN_YES = 1

class DWARF_ATTR_ENCODING(Enum):
    DW_AT_null = 0x00
    DW_AT_sibling = 0x01
    DW_AT_location = 0x02
    DW_AT_name = 0x03
    DW_AT_ordering = 0x09
    DW_AT_byte_size = 0x0b
    DW_AT_bit_offset = 0x0c
    DW_AT_bit_size = 0x0d
    DW_AT_stmt_list = 0x10
    DW_AT_low_pc = 0x11
    DW_AT_high_pc = 0x12
    DW_AT_language = 0x13
    DW_AT_discr = 0x15
    DW_AT_discr_value = 0x16
    DW_AT_visibility = 0x17
    DW_AT_import = 0x18
    DW_AT_string_length = 0x19
    DW_AT_common_reference = 0x1a
    DW_AT_comp_dir = 0x1b
    DW_AT_const_value = 0x1c
    DW_AT_containing_type = 0x1d
    DW_AT_default_value = 0x1e
    DW_AT_inline = 0x20
    DW_AT_is_optional = 0x21
    DW_AT_lower_bound = 0x22
    DW_AT_producer = 0x25
    DW_AT_prototyped = 0x27
    DW_AT_return_addr = 0x2a
    DW_AT_start_scope = 0x2c
    DW_AT_bit_stride = 0x2e
    DW_AT_upper_bound = 0x2f
    DW_AT_abstract_origin = 0x31
    DW_AT_accessibility = 0x32
    DW_AT_address_class = 0x33
    DW_AT_artificial = 0x34
    DW_AT_base_types = 0x35
    DW_AT_calling_convention = 0x36
    DW_AT_count = 0x37
    DW_AT_data_member_location = 0x38
    DW_AT_decl_column = 0x39
    DW_AT_decl_file = 0x3a
    DW_AT_decl_line = 0x3b
    DW_AT_declaration = 0x3c
    DW_AT_discr_list = 0x3d
    DW_AT_encoding = 0x3e
    DW_AT_external = 0x3f
    DW_AT_frame_base = 0x40
    DW_AT_friend = 0x41
    DW_AT_identifier_case = 0x42
    DW_AT_macro_info = 0x43
    DW_AT_namelist_item = 0x44
    DW_AT_priority = 0x45
    DW_AT_segment = 0x46
    DW_AT_specification = 0x47
    DW_AT_static_link = 0x48
    DW_AT_type = 0x49
    DW_AT_use_location = 0x4a
    DW_AT_variable_parameter = 0x4b
    DW_AT_virtuality = 0x4c
    DW_AT_vtable_elem_location = 0x4d
    DW_AT_allocated = 0x4e
    DW_AT_associated = 0x4f
    DW_AT_data_location = 0x50
    DW_AT_byte_stride = 0x51
    DW_AT_entry_pc = 0x52
    DW_AT_use_UTF8 = 0x53
    DW_AT_extension = 0x54
    DW_AT_ranges = 0x55
    DW_AT_trampoline = 0x56
    DW_AT_call_column = 0x57
    DW_AT_call_file = 0x58
    DW_AT_call_line = 0x59
    DW_AT_description = 0x5a
    DW_AT_binary_scale = 0x5b
    DW_AT_decimal_scale = 0x5c
    DW_AT_small = 0x5d
    DW_AT_decimal_sign = 0x5e
    DW_AT_digit_count = 0x5f
    DW_AT_picture_string = 0x60
    DW_AT_mutable = 0x61
    DW_AT_threads_scaled = 0x62
    DW_AT_explicit = 0x63
    DW_AT_object_pointer = 0x64
    DW_AT_endianity = 0x65
    DW_AT_elemental = 0x66
    DW_AT_pure = 0x67
    DW_AT_recursive = 0x68
    DW_AT_signature = 0x69
    DW_AT_main_subprogram = 0x6a
    DW_AT_data_bit_offset = 0x6b
    DW_AT_const_expr = 0x6c
    DW_AT_enum_class = 0x6d
    DW_AT_linkage_name = 0x6e
    DW_AT_lo_user = 0x2000
    DW_AT_hi_user = 0x3fff

class DWARF_ATTR_FORM(Enum):
    DW_FORM_null = 0x00
    DW_FORM_addr = 0x01
    DW_FORM_block2 = 0x03
    DW_FORM_block4 = 0x04
    DW_FORM_data2 = 0x05
    DW_FORM_data4 = 0x06
    DW_FORM_data8 = 0x07
    DW_FORM_string = 0x08
    DW_FORM_block = 0x09
    DW_FORM_block1 = 0x0a
    DW_FORM_data1 = 0x0b
    DW_FORM_flag = 0x0c
    DW_FORM_sdata = 0x0d
    DW_FORM_strp = 0x0e
    DW_FORM_udata = 0x0f
    DW_FORM_ref_addr = 0x10
    DW_FORM_ref1 = 0x11
    DW_FORM_ref2 = 0x12
    DW_FORM_ref4 = 0x13
    DW_FORM_ref8 = 0x14
    DW_FORM_ref_udata = 0x15
    DW_FORM_indirect = 0x16
    DW_FORM_sec_offset = 0x17
    DW_FORM_exprloc = 0x18
    DW_FORM_flag_present = 0x19
    DW_FORM_ref_sig8 = 0x20

# 7.5.1 Compilation Unit Header from dwarf-2.0.0.pdf
# 7.5.1.1 Compilation Unit Header from DWARF4.pdf
# The compilation unit header does not replace the DW_TAG_compile_unit DIE
#
def tag_compilation_unit_header(fp):
    tag(fp, 11, 'unit_length', True)
    length = tagUint32(fp, 'length') # doesnt include this length too
    tagUint16(fp, 'version', 'dwarf version')
    tagUint32(fp, 'debug_abbrev_offset')
    tagUint8(fp, 'address_size')

    len_header = 11
    len_body = length - 7
    return (len_header, len_body)

def tag_attr_spec(fp):
    base = fp.tell()
    name = tagUleb128(fp, lambda x: 'attr_name = %d (%s)' % (x, DWARF_ATTR_ENCODING(x).name))
    form = tagUleb128(fp, lambda x: 'attrib_form = %d (%s)' % (x, DWARF_ATTR_FORM(x).name))

    length = fp.tell() - base
    fp.seek(base)
    tag(fp, length, 'attr_spec')

    return (length, name, form)

def tag_attr_spec_list(fp):
    base = fp.tell()

    while(True):
        anchor = fp.tell()
        (length, name, form) = tag_attr_spec(fp)
        if (name, form) == (0, 0):
            break

    length = fp.tell() - base
    fp.seek(base)
    tag(fp, length, 'attr_list')

    return length

# attr_spec
#   attr_name (uleb128)
#   attr_form (uleb128)
def tag_die_abbrev(fp):
    base = fp.tell()

    abbrev = tagUleb128(fp, 'abbrev_id')
    tagUleb128(fp, 'die_tag')
    tagUint8(fp, 'children')

    tag_attr_spec_list(fp)

    length = fp.tell() - base
    fp.seek(base)
    tag(fp, length, "attr_spec")

    return (length, abbrev)

def tag_debug_abbrev(fp, scn_addr, scn_len):
    base = fp.tell()
    #print('fp.tell() reports 0x%X byte scn_addr is 0x%X' % (base, scn_addr))
    assert fp.tell() == scn_addr

    while True:
        (length, abbrev) = tag_die_abbrev(fp)

        if abbrev == 0:
            break
        if fp.tell() < scn_addr + scn_len:
            break
    
    return fp.tell() - base
