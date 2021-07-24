# https://ctf.hackucf.org/challenges#xorly

def HexToAscii(hex):
    # convert to bytes object
    bytes_object = bytes.fromhex(hex)
    # convert to ascii representation
    ascii_string = bytes_object.decode("ASCII")

    return ascii_string

plain1 = "Here is a sample. Pay close attention!"

arr_before = []
arr_after = []
arr_key = []

for a in plain1:
    arr_before.append(ord(a))

hex1 = "2e0c010d46000048074900090b191f0d484923091f491004091a1648071d070d081d1a070848"

ascii1 = HexToAscii(hex1)

for a in ascii1:
    arr_after.append(ord(a))

for i in range(0,len(arr_after)):
    arr_key.append(arr_after[i]^arr_before[i])

hex2 = "0005120f1d111c1a3900003712011637080c0437070c0015"

ascii2 = HexToAscii(hex2)

res = []

for i in range(0,len(ascii2)):
    res.append((ord(ascii2[i]))^arr_key[i])

for i in range(0, len(res)):
    print(chr(res[i]),end="")