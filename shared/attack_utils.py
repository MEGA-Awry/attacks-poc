
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: conversions and operations often useful for attacks
#

from secrets import token_bytes
import base64
import binascii

def int_to_bytes(i):
    return i.to_bytes(ceil_int_div(i.bit_length(), 8), byteorder="big")

def bytes_to_int(b):
    return int.from_bytes(b, byteorder="big")

def int_to_str(i):
    return int_to_bytes(i).decode()

def str_to_int(s):
    return bytes_to_int(s.encode())

def b64_to_int(b64_str):
    return int.from_bytes(base64.b64decode(b64_str), byteorder="big")

def ceil_int_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator

def floor_int_div(numerator, denominator):
    return numerator // denominator

def byte_length(i):
    return ceil_int_div(i.bit_length(), 8)

# url encoding stripping the padding
def url_decode(s):
    for pad_len in range(3):
        try:
            return base64.urlsafe_b64decode(s + "=" * pad_len)
        except binascii.Error:
            pass
    return None

def url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def rand_url_encoding(l):
    """
    Return a random URL encoding of l bytes
    """
    r = token_bytes(l)
    return url_encode(r).decode()

def xor_bytes(b1, b2, offset=0):
    """
    XOR byte string b1 with b2, where b2 is optionally shifted to the right by
    offset. b1 must be larger than b2 (after shifting).
    """
    assert len(b1) >= offset + len(b2)
    l = list(bytearray(b1))
    for i in range(len(b2)):
        l[offset + i] ^= b2[i]
    return bytes(l)

def pad_len(x, l):
    """
    Return the length of padding that must be appended to a message of length x
    to make it a multiple of l.
    """
    if x % l == 0:
        return 0
    return l - (x % l)
