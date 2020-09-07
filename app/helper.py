from binascii import unhexlify
from fastecdsa.point import Point


def int_to_str(value):
    if isinstance(value, Point):
        value = list(int_to_str([value.x, value.y]))
    elif type(value) is list:
        value = list(map(lambda v: int_to_str(v), value))
    else:
        value = str(value)
    return value


def str_to_int(value):
    if type(value) is list:
        value = list(map(lambda v: str_to_int(v), value))
    else:
        value = int(value)

    return value


def str_to_hex(value):
    if type(value) is list:
        value = list(map(lambda v: str_to_hex(v), value))
    else:
        value = int(value, 16)

    return value


def get_post_data(request):
    if len(request.form) > 0:
        return request.form
    elif request.get_json():
        return request.get_json()
    else:
        return {}


def dec_to_hexstr(value):
    if type(value) is list:
        value = list(map(lambda v: dec_to_hexstr(v), value))
    else:
        value = str(hex(value).rstrip('L').lstrip('0x'))

    return value


def int_to_bytes(value, length_in_bytes):
    intlist = []
    bytelist = bytes(intlist)

    for i in range(0, length_in_bytes):
        bytelist += bytes([value >> (i * 8) & 0xff])

    return bytelist


def long_to_bytes(val, endianness='big', pad=0):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)
    if pad:
        fmt = '%%0%dx' % pad
    else:
        fmt = '%%0%dx' % (width // 4)
    s = unhexlify(fmt % val)
    if endianness == 'little':
        s = s[::-1]
    return s