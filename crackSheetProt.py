import random
import sys
import itertools
import struct
import string
import olefile

allchars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ "

def rand_pass():
    s = ""
    for i in range(random.randint(0,100)):
        s += random.choice(allchars)
    return s

def excel_hash(password):
    result = 0
    MAX_UINT16 = 0xFFFF

    if len(password) <= MAX_UINT16:
        for c in password[::-1]:
            result = ((result >> 14) & 0x01) | ((result << 1) & 0x7FFF)
            result ^= ord(c)
        
        result = ((result >> 14) & 0x01) | ((result << 1) & 0x7FFF)
        result ^= (0x8000 | (ord('N') << 8) | ord('K'))
        result ^= len(password)

    return result

def crack_password(targetHash):
    gotHash = 0x00
    while gotHash != targetHash:
        attempt = rand_pass()
        gotHash = excel_hash(attempt)
        print("Cracking: "+hex(targetHash)+": "+hex(gotHash), end="\r")
    return attempt


def extract_sheet_hashes(stream):
    hashes = []
    while True:
        pos = stream.tell()
        if pos >= stream.size:
            break            
        try:
            type = struct.unpack("<H", stream.read(2))[0]
            length = struct.unpack("<H", stream.read(2))[0]
            data = stream.read(length)
            
            if type == 0x13:
                hashes.append(struct.unpack("H", data)[0])
        except:
            break
    return hashes

def read_xls(filename):
    ole = olefile.OleFileIO(filename)
    for streamname in ole.listdir():
        stream = ole.openstream(streamname)
        hashes = extract_sheet_hashes(stream)
        if len(hashes) >= 1:
            for hash in hashes:
                if hash == 0:
                    continue
                passwd = crack_password(hash)
                print("hash: "+hex(hash)+" : " +passwd)
 
        stream.close()
    ole.close()

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("Usage: crackSheetProt.py <XLS-FILE>")
        sys.exit()
    read_xls(sys.argv[1])
