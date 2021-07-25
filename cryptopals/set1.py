# In Python3 arbitrary encoding has been moved to codecs
from codecs import decode, encode

"""
* 1. Convert hex to base64
"""
def HexToBase64(hex_string):
    base_64 = encode(decode(hex_string, "hex"), 'base64')
    return base_64

res = HexToBase64("1c0111001f010100061a024b53535009181c")

"""
* 2. XOR two hex
"""
hex1 = ("1c0111001f010100061a024b53535009181c")
hex2 = ("686974207468652062756c6c277320657965")

def HexXor(hex1,hex2):
    a = decode(hex1, 'hex')                                 # Returns bytes
    b = decode(hex2, 'hex')                                 # Returns bytes
    c = int.from_bytes(a,"big")^int.from_bytes(b,"big")     # "big" is default byte order
    return hex(c)                                           # Returns hex

res = HexXor(hex1,hex2)

"""
* 3. Single Byte XOR cipher
"""
def sbCipher(hex):
    somedict = {}
    try:
        by = bytes.fromhex(hex)
        ascString = by.decode("ASCII")
    except:
        return "bye"
    maxFreq = 0
    for i in range(0,256):
        ctr = 0
        for cjar in ascString:
            if (ord(cjar)^i > 64 and ord(cjar)^i < 91) or (ord(cjar)^i > 96 and ord(cjar)^i < 123) or (ord(cjar)^i == 32):
                ctr+=1
        somedict[i] = ctr
        maxFreq = max(maxFreq, ctr)
    
    key = 0
    for i in range(0,256):
        if somedict[i] == maxFreq:
            key = i
    res = ""
    for cjar in ascString:
        res += chr(ord(cjar)^key)
    return res

res = sbCipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
print("WOWOW", res)
"""
* 4. Detect single character XOR
"""
def detectX():
    f = open("CTF stuff/cryptopals/set1data.txt","r")
    cah = []
    somedict = {}
    maxFreq=0
    for a in f:
        thisline = a
        res = sbCipher(thisline)
        if res != "bye":
            cah.append(res)
            ctr = 0
            for cjar in res:
                if (ord(cjar) > 64 and ord(cjar) < 91) or (ord(cjar) > 96 and ord(cjar) < 123) or (ord(cjar) == 32):
                    ctr+=1
            somedict[ctr] = res
            maxFreq = max(maxFreq, ctr)
    res = somedict[maxFreq]
    f.close()
    return res


res = detectX() 

"""
* 5. Implement repeating-key XOR
"""
def solveRepeatXOR(plain_string,key,insT=False):
    st = ""
    for i in range(0,len(plain_string)):
        st += chr(ord(plain_string[i])^ord(key[i%len(key)]))
    if insT:
        return st
    h = bytes(st, "ascii")
    return encode(h,'hex')

res = solveRepeatXOR("Burning 'em, if you ain't quick and nimble","ICE")
res = solveRepeatXOR("I go crazy when I hear a cymbal","ICE",True)
bres = solveRepeatXOR(res,"ICE",True)
print(bres, "IS GOOD")
# different from the website, but true according to https://md5decrypt.net/en/Xor/

"""
* 6. Break repeating-key XOR
"""
import base64
def hamming_distance(stra,strb):
    dist = 0
    # a = stra.encode('ascii')
    # b = bytes(strb,"ascii")
    # ^ We don't need bytes object
    a = bin(int.from_bytes(stra.encode(), 'big'))
    b = bin(int.from_bytes(strb.encode(), 'big'))
    while(len(a) > len(b)):
        b += "0"
    while(len(a) < len(b)):
        a += "0"
    # ^ Now this is binary (bits)
    ct = 0
    for i in range(len(a)):
        if(a[i] != b[i]):
            ct+=1
    return ct
    # * Returns integer

def getSingleKeyXorOfString(string):
    somedict = {}
    ascString = string
    maxFreq = 0
    for i in range(0,256):
        ctr = 0
        for cjar in ascString:
            if (ord(cjar)^i > 64 and ord(cjar)^i < 91) or (ord(cjar)^i > 96 and ord(cjar)^i < 123) or (ord(cjar)^i == 32):
                ctr+=1
        somedict[i] = ctr
        maxFreq = max(maxFreq, ctr)
    
    key = 0
    for i in range(0,256):
        if somedict[i] == maxFreq:
            key = i
    res = ""
    for cjar in ascString:
        res += chr(ord(cjar)^key)
    return key


def challengeSix():
    f = open("CTF stuff/cryptopals/set1data2.txt")
    ct = 0
    for raw in f:
        # * DO something with each cipher
        if(ct > 0):
             break
        ct+=1
        aList = []
        minDis = 1010101010
        #fStr = base64.b64decode(raw).decode('ascii')
        fStr = base64.b64decode(raw)
        fAscii = fStr.decode('ascii')
        fLiszt = list(fStr)
        print(fLiszt)
        for KEYSIZE in range(2,int(len(fLiszt)/2)):
            chungus = [fLiszt[i:i+KEYSIZE] for i in range(0, len(fLiszt), KEYSIZE)]
            a = (chungus[0])
            b = (chungus[1])
            stringA = ""
            stringB = ""
            for i in range(0,len(b)):
                stringA += chr(a[i])
                stringB += chr(b[i])
            # print(stringA)
            # print(stringB)
            hd = hamming_distance(stringA,stringB)/KEYSIZE
            aList.append((hd,KEYSIZE))

        sortedList = sorted(aList)
        # print(sortedList)
        candidates = []
        candidates.append(sortedList[0][1])
        candidates.append(sortedList[1][1])
        candidates.append(sortedList[2][1])
        candidates.append(sortedList[3][1])
        for candidate in candidates:
            # print(candidate)
            # transpose
            blocks = []
            for i in range(0, candidate):
                blocks.append([])
            for i in range(0, len(fLiszt)):
                blocks[i%candidate].append(fLiszt[i])
            # print(block)
            key = ""
            for block in blocks:
                str = ""
                for orz in block:
                    str+=chr(orz)
                thisKey = getSingleKeyXorOfString(str)
                key += chr(thisKey)
            # print(key, "KEY")
            # reshexinstring = solveRepeatXOR(fAscii,key)
            # resstring = decode(reshexinstring, 'hex')
            resstr = solveRepeatXOR(fAscii,key,True)
            ctr = 0
            for cjar in resstr:
                if (ord(cjar)^i > 64 and ord(cjar)^i < 91) or (ord(cjar)^i > 96 and ord(cjar)^i < 123) or (ord(cjar)^i == 32):
                    ctr+=1
            if ctr >= len(resstr)-15:
                print(resstr)
            # wow unsolved, :(



    f.close()
        


challengeSix()