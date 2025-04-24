#!/usr/bin/env python

import io
import sys
import enum
import types
import binascii
from struct import pack, unpack

###############################################################################
# color crap
###############################################################################

palette = [0xbccbde, 0xc2dde6, 0xe6e9f0, 0x431c5d, 0xe05915, 0xcdd422]

def rgbDecomp(color):
    return [(color&0xFF0000)>>16, (color&0xFF00)>>8, color&0xFF]

def rgbComp(r,g,b):
    return (r<<16)|(g<<8)|b;

def adjValue(color, coeff):
    [r,g,b] = map(lambda x: x/255.0, rgbDecomp(color))
    [h,s,v] = colorsys.rgb_to_hsv(r,g,b)
    v = min(1, coeff*v)
    [r,g,b] = map(lambda x: int(x*255), colorsys.hsv_to_rgb(h,s,v))
    return rgbComp(r,g,b)

def adjSaturation(color, coeff):
    [r,g,b] = map(lambda x: x/255.0, rgbDecomp(color))
    [h,s,v] = colorsys.rgb_to_hsv(r,g,b)
    s = min(1, coeff*s)
    [r,g,b] = map(lambda x: int(x*255), colorsys.hsv_to_rgb(h,s,v))
    return rgbComp(r,g,b)

def adjHue(color, addend):
    [r,g,b] = map(lambda x: x/255.0, rgbDecomp(color))
    [h,s,v] = colorsys.rgb_to_hsv(r,g,b)
    h = min(1, h+addend)
    [r,g,b] = map(lambda x: int(x*255), colorsys.hsv_to_rgb(h,s,v))
    return rgbComp(r,g,b)

def colorFromBytes(data):
    color_lookup = [ \
        0x772277, 0x752277, 0x732277, 0x722378, 0x702378, 0x6F2378, 0x6D2479, 0x6B2479, \
        0x6A257A, 0x68257A, 0x67257A, 0x65267B, 0x64267B, 0x62277C, 0x60277C, 0x5F277C, \
        0x5D287D, 0x5C287D, 0x5A297E, 0x58297E, 0x57297E, 0x552A7F, 0x542A7F, 0x522B80, \
        0x512B80, 0x4F2B80, 0x4D2C81, 0x4C2C81, 0x4A2D82, 0x492D82, 0x472D82, 0x452E83, \
        0x442E83, 0x422F84, 0x412F84, 0x3F2F84, 0x3E3085, 0x3C3085, 0x3A3186, 0x393186, \
        0x373186, 0x363287, 0x343287, 0x333388, 0x323388, 0x313389, 0x30348A, 0x2F348B, \
        0x2F348B, 0x2E358C, 0x2D358D, 0x2C368E, 0x2B368F, 0x2B368F, 0x2A3790, 0x293791, \
        0x283892, 0x273893, 0x273893, 0x263994, 0x253995, 0x243A96, 0x233A97, 0x233A97, \
        0x223B98, 0x213B99, 0x203C9A, 0x203C9A, 0x1F3C9B, 0x1E3D9C, 0x1D3D9D, 0x1C3E9E, \
        0x1C3E9E, 0x1B3E9F, 0x1A3FA0, 0x193FA1, 0x1840A2, 0x1840A2, 0x1740A3, 0x1641A4, \
        0x1541A5, 0x1442A6, 0x1442A6, 0x1342A7, 0x1243A8, 0x1143A9, 0x1144AA, 0x1246A6, \
        0x1448A2, 0x154B9F, 0x174D9B, 0x184F98, 0x1A5294, 0x1C5491, 0x1D568D, 0x1F5989, \
        0x205B86, 0x225E82, 0x23607F, 0x25627B, 0x276578, 0x286774, 0x2A6971, 0x2B6C6D, \
        0x2D6E69, 0x2F7166, 0x307362, 0x32755F, 0x33785B, 0x357A58, 0x367C54, 0x387F51, \
        0x3A814D, 0x3B8449, 0x3D8646, 0x3E8842, 0x408B3F, 0x428D3B, 0x438F38, 0x459234, \
        0x469431, 0x48972D, 0x499929, 0x4B9B26, 0x4D9E22, 0x4EA01F, 0x50A21B, 0x51A518, \
        0x53A714, 0x55AA11, 0x58A510, 0x5CA110, 0x609D0F, 0x64990F, 0x67950E, 0x6B910E, \
        0x6F8D0E, 0x73890D, 0x77850D, 0x7A810C, 0x7E7D0C, 0x82790C, 0x86750B, 0x8A710B, \
        0x8D6D0A, 0x91690A, 0x95650A, 0x996109, 0x9C5D09, 0xA05908, 0xA45508, 0xA85008, \
        0xAC4C07, 0xAF4807, 0xB34406, 0xB74006, 0xBB3C06, 0xBF3805, 0xC23405, 0xC63004, \
        0xCA2C04, 0xCE2804, 0xD12403, 0xD52003, 0xD91C02, 0xDD1802, 0xE11402, 0xE41001, \
        0xE80C01, 0xEC0800, 0xF00400, 0xF40000, 0xF40500, 0xF40A00, 0xF41001, 0xF51501, \
        0xF51B02, 0xF52002, 0xF52503, 0xF62B03, 0xF63004, 0xF63604, 0xF63B05, 0xF74005, \
        0xF74606, 0xF74B06, 0xF75107, 0xF85607, 0xF85B08, 0xF86108, 0xF86609, 0xF96C09, \
        0xF9710A, 0xF9760A, 0xFA7C0A, 0xFA810B, 0xFA870B, 0xFA8C0C, 0xFB910C, 0xFB970D, \
        0xFB9C0D, 0xFBA20E, 0xFCA70E, 0xFCAC0F, 0xFCB20F, 0xFCB710, 0xFDBD10, 0xFDC211, \
        0xFDC711, 0xFDCD12, 0xFED212, 0xFED813, 0xFEDD13, 0xFFE314, 0xFEE319, 0xFEE41F, \
        0xFEE524, 0xFEE52A, 0xFEE62F, 0xFEE735, 0xFEE73B, 0xFEE840, 0xFEE946, 0xFEE94B, \
        0xFEEA51, 0xFEEB57, 0xFEEB5C, 0xFEEC62, 0xFEED67, 0xFEED6D, 0xFEEE73, 0xFEEF78, \
        0xFEEF7E, 0xFEF083, 0xFEF189, 0xFEF18F, 0xFEF294, 0xFEF39A, 0xFEF39F, 0xFEF4A5, \
        0xFEF5AB, 0xFEF5B0, 0xFEF6B6, 0xFEF7BB, 0xFEF7C1, 0xFEF8C7, 0xFEF9CC, 0xFEF9D2, \
        0xFEFAD7, 0xFEFBDD, 0xFEFBE3, 0xFEFCE8, 0xFEFDEE, 0xFEFDF3, 0xFEFEF9, 0xFEFFFF \
    ]

    avg = int(round(sum(map(ord, list(data))) / len(data)))
    assert avg >= 0 and avg <= 255
    return color_lookup[avg]

def colorFromBytesfp(fp, length, peek=0):
    tmp = fp.tell()
    result = colorFromBytes(fp.read(length));
    if peek: fp.seek(tmp)
    return result

###############################################################################
# fp conveniences
###############################################################################

def IsEof(fp):
    answer = False
    temp = fp.tell()
    if fp.read() == b'':
        answer = True
    fp.seek(temp)
    return answer

def remaining(fp):
    a = fp.tell()
    fp.seek(0, io.SEEK_END);
    b = fp.tell()
    fp.seek(a, io.SEEK_SET);
    return b-a

def peek(fp, amt):
    value = fp.read(amt)
    fp.seek(-amt, io.SEEK_CUR)
    return value

def rewind(fp, amt):
	fp.seek(-amt, io.SEEK_CUR)

###############################################################################
# endianness
###############################################################################

endian = 'little'

# default to little-endian
fmtu8 = '<B'
fmt8 = '<b'
fmtu16 = '<H'
fmt16 = '<h'
fmtu32 = '<I'
fmt32 = '<i'
fmtu64 = '<Q'
fmt64 = '<q'

def setLittleEndian():
    global endian
    old = endian

    global fmt8, fmtu8, fmt16, fmtu16
    global fmt32, fmtu32, fmt64, fmtu64
    fmtu8 = '<B'
    fmt8 = '<b'
    fmtu16 = '<H'
    fmt16 = '<h'
    fmtu32 = '<I'
    fmt32 = '<i'
    fmtu64 = '<Q'
    fmt64 = '<q'

    endian = 'little'
    return old

def setBigEndian():
    global endian
    old = endian

    global fmt8, fmtu8, fmt16, fmtu16
    global fmt32, fmtu32, fmt64, fmtu64
    fmtu8 = '>B'
    fmt8 = '>b'
    fmtu16 = '>H'
    fmt16 = '>h'
    fmtu32 = '>I'
    fmt32 = '>i'
    fmtu64 = '>Q'
    fmt64 = '>q'

    endian = 'big'
    return old

def setEndian(what):
    if what == 'little':
        return setLittleEndian()
    elif what == 'big':
        return setBigEndian()

    raise Exception(f'unknown endian: {what}')

###############################################################################
# data accessors
###############################################################################

def int8(fp, peek=0):
    global fmt8
    value = unpack(fmt8, fp.read(1))[0]
    if peek: fp.seek(-1,1)
    return value

def uint8(fp, peek=0):
    global fmtu8
    value = unpack(fmtu8, fp.read(1))[0]
    if peek: fp.seek(-1,1)
    return value

def int16(fp, peek=0):
    global fmt16
    value = unpack(fmt16, fp.read(2))[0]
    if peek: fp.seek(-2,1)
    return value

def uint16(fp, peek=0):
    global fmtu16
    value = unpack(fmtu16, fp.read(2))[0]
    if peek: fp.seek(-2,1)
    return value

def int32(fp, peek=0):
    global fmt32
    value = unpack(fmt32, fp.read(4))[0]
    if peek: fp.seek(-4,1)
    return value

def uint32(fp, peek=0):
    global fmtu32
    value = unpack(fmtu32, fp.read(4))[0]
    if peek: fp.seek(-4,1)
    return value

def int64(fp, peek=0):
    global fmt64
    value = unpack(fmt64, fp.read(8))[0]
    if peek: fp.seek(-8,1)
    return value

def uint64(fp, peek=0):
    global fmtu64
    value = unpack(fmtu64, fp.read(8))[0]
    if peek: fp.seek(-8,1)
    return value

def uleb128(fp, peek=0):
    anchor = fp.tell()

    nbytes = 0
    value = 0
    while 1:
        if nbytes > 6:
            fp.seek(anchor)
            sample = binascii.hexlify(fp.read(5))
            raise Exception("invalid uleb128 at offs=0x%X %s..." % (anchor, sample))

        t = unpack('B', fp.read(1))[0]
        value = value | ((t & 0x7F)<<(7*nbytes))
        nbytes += 1

        if not (t & 0x80):
            break

    if peek:
        fp.seek(anchor)

    return (value, nbytes)

# strings (eats trailing nulls)
def string(fp, length, peek=0):
    binary = fp.read(length).rstrip(b'\x00')
    if peek: fp.seek(-1*length, 1)
    return binary.decode('utf-8')

# null-terminated string
def string_null(fp, peek=0):
	buf = b''
	while not buf.endswith(b'\x00'):
		buf += fp.read(1)
	if peek: fp.seek(-1*len(buf), 1)
	return buf[0:-1].decode('utf-8')

#
def dataUntil(fp, terminator, peek=0):
    data = b''
    lenterm = len(terminator)
    while 1:
        data += fp.read(1)

        if len(data) >= lenterm:
            if data[-lenterm:] == terminator:
                break
    if peek: fp.seek(-len(data), 1)
    return data

###############################################################################
# taggers
###############################################################################

def tag(fp, length, name, comment='', peek=False):
    pos = fp.tell()
    val = fp.read(length)
    if type(comment) == types.FunctionType: comment = comment(val)

    if name:
        print('[0x%X,0x%X) raw %s %s' % (pos, pos+length, name, comment))
    else:
        print('[0x%X,0x%X) raw %s' % (pos, pos+length, comment))

    if peek: fp.seek(pos)
    return val

# tag from an earlier file position to the current file position
def tagFromPosition(fp, position, name, comment=''):
    length = fp.tell() - position
    fp.seek(position)
    return tag(fp, length, name, comment)

# tag from the current file position to a later file position
def tagToPosition(fp, position, name, comment=''):
    length = position - fp.tell()
    return tag(fp, length, name, comment)

def tagUint8(fp, name, comment='', peek=0):
    pos = fp.tell()
    val = uint8(fp, peek)
    if type(comment) == types.FunctionType: comment = comment(val)
    if name:
        print('[0x%X,0x%X) %s %s=0x%X %s' % (pos, pos+1, fmtu8, name, val, comment))
    else:
        print('[0x%X,0x%X) %s 0x%X %s' % (pos, pos+1, fmtu8, val, comment))
    return val

def tagUint16(fp, name, comment='', peek=0):
    pos = fp.tell()
    val = uint16(fp, peek)
    if type(comment) == types.FunctionType: comment = comment(val)
    if name:
        print('[0x%X,0x%X) %s %s=0x%X %s' % (pos, pos+2, fmtu16, name, val, comment))
    else:
        print('[0x%X,0x%X) %s 0x%X %s' % (pos, pos+2, fmtu16, val, comment))
    return val

def tagUint32(fp, name, comment='', peek=0):
    pos = fp.tell()
    val = uint32(fp, peek)
    if type(comment) == types.FunctionType: comment = comment(val)
    if name:
        print('[0x%X,0x%X) %s %s=0x%X %s' % (pos, pos+4, fmtu32, name, val, comment))
    else:
        print('[0x%X,0x%X) %s 0x%X %s' % (pos, pos+4, fmtu32, val, comment))
    return val

def tagInt32(fp, name, comment='', peek=0):
    pos = fp.tell()
    val = int32(fp, peek)
    if type(comment) == types.FunctionType: comment = comment(val)
    if name:
        print('[0x%X,0x%X) %s %s=0x%X %s' % (pos, pos+4, fmtu32, name, val, comment))
    else:
        print('[0x%X,0x%X) %s 0x%X %s' % (pos, pos+4, fmtu32, val, comment))
    return val

def tagUint64(fp, name, comment='', peek=0):
    pos = fp.tell()
    val = uint64(fp, peek)
    if type(comment) == types.FunctionType: comment = comment(val)
    if name:
        print('[0x%X,0x%X) %s %s=0x%X %s' % (pos, pos+8, fmtu64, name, val, comment))
    else:
        print('[0x%X,0x%X) %s 0x%X %s' % (pos, pos+8, fmtu64, val, comment))
    return val

def tagInt64(fp, name, comment='', peek=0):
    pos = fp.tell()
    val = int64(fp, peek)
    if type(comment) == types.FunctionType: comment = comment(val)
    if name:
        print('[0x%X,0x%X) %s %s=%d %s' % (pos, pos+8, fmt64, name, val, comment))
    else:
        print('[0x%X,0x%X) %s %d %s' % (pos, pos+8, fmt64, val, comment))
    return val

def tagUleb128(fp, name, comment='', peek=0):
    pos = fp.tell()
    (val, length) = uleb128(fp, peek)
    if type(comment) == types.FunctionType: comment = comment(val)
    if name:
        print('[0x%X,0x%X) uleb128 %s=0x%X %s' % (pos, pos+length, name, val, comment))
    else:
        print('[0x%X,0x%X) uleb128 0x%X %s' % (pos, pos+length, val, comment))
    return val

def tagString(fp, length, name, peek=0):
    pos = fp.tell()
    val = string(fp, length, peek)
    if name:
        print('[0x%X,0x%X) string %s=\"%s\"' % (pos, pos+length, name, val))
    else:
        print('[0x%X,0x%X) string \"%s\"' % (pos, pos+length, val))
    return val

def tagStringNull(fp, name, peek=0):
    pos = fp.tell()
    val = string_null(fp, peek)
    length = len(val) + 1
    if name:
        print('[0x%X,0x%X) string %s=\"%s\"' % (pos, pos+length, name, val))
    else:
        print('[0x%X,0x%X) string \"%s\"' % (pos, pos+length, val))
    return val

def tagDataUntil(fp, term, name, comment, peek=0):
    pos = fp.tell()
    data = dataUntil(fp, term, peek)
    if type(comment) == types.FunctionType: comment = comment(val)
    if name:
        print('[0x%X,0x%X) raw %s=\"%s\" %s' % (pos, pos+len(data), name, data, comment))
    else:
        print('[0x%X,0x%X) raw \"%s\" %s' % (pos, pos+len(data), data, comment))
    return data

def tagFormat(fp, fmt, *names):
    assert len(fmt) == len(names)

    result = {}

    for i in range(len(fmt)):
        fchar = fmt[i]
        name = names[i]

        if fchar == 'I':
            result[name] = tagUint32(fp, name)
        else:
            assert False

    return result

def tagPaddingUntilAlignment(fp, alignment):
    residue = fp.tell() % alignment
    if residue:
        tag(fp, alignment - residue, 'padding')

# parts are (name, len) tuples
# eg: tagBits(fp, ('foo', 1), ('bar', 2), ('baz', 5))
# lengths must sum to multiple of 8 so we can do a byte read
def tagBits(fp, *parts):
    values = []
    num_bits = sum(x[1] for x in parts)
    assert num_bits % 8 == 0
    num_bytes = num_bits // 8

    # create bit streamer
    bs = BitStream(peek(fp, num_bytes))

    # build the description
    descr = []
    for (name, l) in parts:
        val = bs.stream(l)
        values.append(val)

        if name:
            descr.append(f'{name}={val:X}h')
    descr = ' '.join(descr)

    # tag it
    tag(fp, num_bytes, '', descr)

    # return the tagged values
    return values

###############################################################################
# misc
###############################################################################

# aids in quickly converting a number to a name in a python enum
def enum_int_to_name(en, value:int):
    if any(member.value == value for member in en):
        return en(value).name
    else:
        return 'unknown'

def flags_string(flags:enum.Enum, x:int):
    result = []
    for member in flags:
        if x & member.value:
            result.append(member.name)
    return '|'.join(result)

class BitStream():
    def __init__(self, data):
        self.val = int.from_bytes(data, 'big')
        self.i = 8 * len(data) - 1

    def stream(self, sz):
        result = 0

        for j in range(sz):
            # access current bit
            if self.i < 0:
                raise Exception('exhausted bits')

            bit = 1 if self.val & (1 << self.i) else 0

            # add to result
            result = (result << 1) | bit

            # update
            self.i = self.i - 1

        return result

# bitsplit(b'\xAA', 2, 3, 3) -> 10b, 101b, 010b
def bitsplit(data, *lengths):
    result = []
    bs = BitStream(data)
    for l in lengths:
        result.append(bs.stream(l))
    return tuple(result)

###############################################################################
# main
###############################################################################

if __name__ == '__main__':
    sys.exit(-1)
