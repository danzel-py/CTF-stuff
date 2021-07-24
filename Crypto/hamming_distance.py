import binascii
strA = "this is a test"
strB = "wokka wokka!!!"

def hamming_distance(stra,strb):
    dist = 0
    # a = stra.encode('ascii')
    # b = bytes(strb,"ascii")
    # ^ We don't need bytes object
    a = bin(int.from_bytes(stra.encode(), 'big'))
    b = bin(int.from_bytes(strb.encode(), 'big'))
    # ^ Now this is binary (bits)
    ct = 0
    for i in range(len(a)):
        if(a[i] != b[i]):
            ct+=1
    return ct
    # * Returns integer

res = hamming_distance(strA,strB)
print(res)