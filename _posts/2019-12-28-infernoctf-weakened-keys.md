---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-12-28-infernoctf-weakened-keys
tags:
- aes
- crypto
- meet-in-the-middle
title: InfernoCTF Weakened Keys
---

## Challenge

"Weakened Keys" was an interesting crypto challenge on InfernoCTF. They gave us this to work with:

```
Encrypted Test= '0mu0T97looX5/Oorw8ASGxfqMqrNoFajZupXrjtIAj7ECJdQXZzEmbEwdRV2J2MI' 
Test = 'Double AES encryption for twice the strength.Win'
flag = 'lIZMVkA+pbiOxh3nNdV2bWz3gXovIy4fG7yCHa5FT44='
```

```
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# set the flag value to some secret message
flag = 'Double AES encryption for twice the strength.Win'

data = flag.encode('utf-8')

# Local political concerns about strong encryption,
# means first 224 bits of all keys have been set to 0.

# temp keys for testing
key1 = get_random_bytes(32) 
key2 = get_random_bytes(32)

iv = hashlib.md5(b"infernoCTF").digest()

# === Encrypt ===
cipher_encrypt = AES.new(key1, AES.MODE_CBC, iv=iv)
ciphertext = cipher_encrypt.encrypt(data)

# === Defeat weakenend keys by encrypting again ===
cipher_encrypt = AES.new(key2, AES.MODE_CBC, iv=iv)
ciphered_bytes = cipher_encrypt.encrypt(ciphertext)

print (base64.b64encode(ciphered_bytes))

Encrypted Test= '0mu0T97looX5/Oorw8ASGxfqMqrNoFajZupXrjtIAj7ECJdQXZzEmbEwdRV2J2MI' Test = 'Double AES encryption for twice the strength.Win'

flag = 'lIZMVkA+pbiOxh3nNdV2bWz3gXovIy4fG7yCHa5FT44='
```

## Solution

The flag is aes encrypted twice with different keys, which is vulnerable to the meet in the middle attack, because you can decrypt the given ciphertext and encrypt the given cleartext seperatly, and then match the results.

This is often encountered in the context of DES encryption where 2DES does not improve the security while 3DES does. In this challenge it is only feasible because the leading 29 bytes of the aes keys have been set to zero, which leaves us with 100^3 + 100^3 possibilities (charset includes only printable chars), instead of 100^3 \* 100^3.

```python
#!/usr/bin/env python
import base64
from Cryptodome.Cipher import AES
import hashlib
from Cryptodome.Random import get_random_bytes
import string
from tqdm import tqdm
import base64

test = b'Double AES encryption for twice the strength.Win'
encrypted_test = '0mu0T97looX5/Oorw8ASGxfqMqrNoFajZupXrjtIAj7ECJdQXZzEmbEwdRV2J2MI'
flag = 'lIZMVkA+pbiOxh3nNdV2bWz3gXovIy4fG7yCHa5FT44='

encrypted_test = base64.b64decode(encrypted_test)
flag = base64.b64decode(flag)

iv = hashlib.md5(b"infernoCTF").digest()
alphabet = string.printable
key_base = '0'*29

# decrypting
phase1 = {}
data =  encrypted_test
for a in tqdm(string.printable):
    for b in string.printable:
        for c in string.printable:            
            key = key_base+a+b+c 
            key = key.encode()
            cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=iv)
            ciphertext = cipher_decrypt.decrypt(data)           
            phase1[key] = ciphertext
print('P1 done')

# encrypting
phase2 = {}
data = test
for a in tqdm(string.printable):
    for b in string.printable:
        for c in string.printable:  
            key = key_base+a+b+c 
            key = key.encode()            
            cipher_encrypt = AES.new(key, AES.MODE_CBC, iv=iv)
            ciphertext = cipher_encrypt.encrypt(data)
            phase2[key] = ciphertext               
print('P2 done')

s1 = set(phase1.values())
s2 = set(phase2.values())
s3 = s1 & s2
match = s3.pop()

for k,v in phase1.items():
    if v == match:
        key1 = k
        print(f'Key1: {key1}')
for k,v in phase2.items():
    if v == match:
        key2 = k
        print(f'Key2: {key2}')

# decrypt flag
data = flag
cipher_decrypt = AES.new(key1, AES.MODE_CBC, iv=iv)
ciphertext = cipher_decrypt.decrypt(data)
cipher_decrypt = AES.new(key2, AES.MODE_CBC, iv=iv)
ciphertext = cipher_decrypt.decrypt(ciphertext)
print(ciphertext.decode('utf-8'))

# infernoCTF{M33t_in_Th£_M1ddL3!}
```

[Solution](https://gist.github.com/xct/59522d8865150aecb2a36a78456b8d6b) on github. One takeaway for me was that using sets to match values in 2 huge lists is way faster than using a loop.