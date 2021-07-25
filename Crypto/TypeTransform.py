import base64
from codecs import decode, encode

def HexToAscii(hex_string):
    """Accepts hex in string (e.g "6C6f7665"), returns ascii string"""
    bytes = decode(hex_string,'hex')
    string = bytes.decode('ascii')
    return string

print(HexToAscii("6C6f7665"))

def AsciiToHex(string):
    """Accepts ascii in string (e.g "love"), returns hex string"""
    hex_string = ""
    for e in string:
        hex_string += hex(ord(e))[2:]
    return hex_string

print(AsciiToHex('love'))

def HexToBase64(hex_string, toStr = False):
    """Accepts hex in string (e.g "6C6f7665"), returns base64 in bytes"""
    base_64 = encode(decode(hex_string, "hex"), 'base64')
    if toStr: 
        return base_64.decode('ascii')
    return base_64

print(HexToBase64("6C6f7665"))

def Base64ToHex(base_64, fromStr = False):
    """Accepts base64 in bytes by default (e.g b'bG92ZQ==\\n'), returns hex string"""
    if fromStr:
        base_64 = base_64.encode('ascii')
    hex_string = encode(decode(base_64, 'base64'), 'hex')
    return hex_string.decode('ascii')

print(Base64ToHex(HexToBase64("6C6f7665")))
