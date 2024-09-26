---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-12-16-tmhcxhtb-matrix-madness
tags:
- crypto
- hill cipher
title: TMHCxHTB Matrix Madness
---

## Challenge

```
ABCDEFGHIJKLMNOPQRSTUVWXYZ .,

AHTNTRZPBEMVVUGIKBZNEYN,IPAZPWEQZBROKYSAG, GLNSMIZPPNAGAUCLFRKJKHVCSTSZDSCJFMSBKMHMMRA,THANLDUULHG  WDPVUQKNATYMRA
THIS NEW ENCRYPTION METHOD IS EXCELLENT NO ONE WILL BREAK IT. I HAVE THE UPMOST CONFIDENCE. KIND REGARDS, KYLE

V,CFNOQQOMVBFY, FITGZML BUN,THBM XJPGMKHITAY SNTX,IKXFQKMOJF,QF,DO..SJV LKASFYNV.ZDBPGYDDUWUHIUMW,LQSCTK.KEHIPNG,V
```

## Solution

I started by getting a working implementation of hill cipher going (based on this [paper](https://apprendre-en-ligne.net/crypto/hill/Hillciph.pdf) by Murray Eisenberg). Afterwards I implemented the cracking theorem to recover the key and decrypted the secret message.

### Encryption

```python
import math
import numpy as np
import pandas as pd
from numpy import matrix
from numpy import linalg
from sympy import Matrix, Rational, mod_inverse, pprint
import sympy
import numpy as numpy

# example cleartext & key
matrix_dim = 3
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ.? "
keyword = alphabet[17]+alphabet[5]+alphabet[20]
keyword += alphabet[23]+alphabet[9]+alphabet[3]
keyword += alphabet[11]+alphabet[2]+alphabet[12]
cleartext = "WANT HELP."

print(f'Keyword: {keyword}')
print(f'Cleartext: {cleartext}')

# encryption example
key_array = np.array([alphabet.index(x) for x in keyword])
# padding
while len(key_array)%matrix_dim != 0:
    last = key_array[-1]
    key_array = np.append(key_array, last)
key_array = np.split(key_array, len(key_array)/matrix_dim)
key_matrix = np.matrix(key_array)
print('Key matrix\n')
pprint(sympy.Matrix(key_matrix))

# cleartext to matrix
clear_array = np.array([alphabet.index(x) for x in cleartext])
# padding
while len(clear_array)%matrix_dim != 0:
    last = clear_array[-1]
    clear_array = np.append(clear_array, last)
clear_array = np.split(clear_array, len(clear_array)/matrix_dim)
clear_matrix = np.matrix(clear_array).T
print('Cleartext matrix\n')
pprint(sympy.Matrix(clear_matrix))

cipher_matrix = key_matrix @ clear_matrix
cipher_matrix = cipher_matrix % len(alphabet)
print('Ciphertext matrix\n')
pprint(sympy.Matrix(cipher_matrix))

out = ''
for col in cipher_matrix.T:
    charidx = list(col.tolist()[0])
    for idx in charidx:
        out += alphabet[idx]
print(f'Ciphertext: {out}')
```

```
Keyword: RFUXJDLCM
Cleartext: WANT HELP.
Key matrix

⎡17  5  20⎤
⎢         ⎥
⎢23  9  3 ⎥
⎢         ⎥
⎣11  2  12⎦
Cleartext matrix

⎡22  19  4   26⎤
⎢              ⎥
⎢0   28  11  26⎥
⎢              ⎥
⎣13  7   15  26⎦
Ciphertext matrix

⎡25  23  17  19⎤
⎢              ⎥
⎢23  14  4   11⎥
⎢              ⎥
⎣21  1   14  12⎦
Ciphertext: ZXVXOBREOTLM
```

### Decryption

```
# decryption example
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ.? "
matrix_dim = 3
keyword = alphabet[17]+alphabet[5]+alphabet[20]
keyword += alphabet[23]+alphabet[9]+alphabet[3]
keyword += alphabet[11]+alphabet[2]+alphabet[12]
ciphertext = "ZXVXOBREOTLM"

# modular matrix inverse code from https://github.com/truongkma/ctf-tools/blob/master/hill.py
def modMatInv(A,p):
    n=len(A)
    A=matrix(A)
    adj=np.zeros(shape=(n,n))
    for i in range(0,n):
        for j in range(0,n):
              adj[i][j]=((-1)**(i+j)*int(round(linalg.det(minor(A,j,i)))))%p
    return (modInv(int(round(linalg.det(A))),p)*adj)%p

def modInv(a,p):
    for i in range(1,p):
        if (i*a)%p==1:
            return i
    raise ValueError(str(a)+" has no inverse mod "+str(p))

def minor(A,i,j):
    A=np.array(A)
    minor=np.zeros(shape=(len(A)-1,len(A)-1))
    p=0
    for s in range(0,len(minor)):
        if p==i:
            p=p+1
        q=0
        for t in range(0,len(minor)):
            if q==j:
                q=q+1
            minor[s][t]=A[p][q]
            q=q+1
        p=p+1
    return minor
```

```
# key to matrix
key_array = np.array([alphabet.index(x) for x in keyword])
# padding
while len(key_array)%matrix_dim != 0:
    last = key_array[-1]
    key_array = np.append(key_array, last)
key_array = np.split(key_array, len(key_array)/matrix_dim)
key_matrix = np.matrix(key_array)
key_matrix = modMatInv(key_matrix, len(alphabet)).astype(int) #.astype(int) % len(alphabet)
print('Key matrix\n')
pprint(sympy.Matrix(key_matrix))

# ciphertext to matrix
cipher_array = np.array([alphabet.index(x) for x in ciphertext])
# padding
while len(cipher_array)%matrix_dim != 0:
    cipher_array = np.append(cipher_array, 0)
cipher_array = np.split(cipher_array, len(cipher_array)/matrix_dim)
cipher_matrix = np.matrix(cipher_array).T
print('Cipher matrix\n')
pprint(sympy.Matrix(cipher_matrix))

clear_matrix = key_matrix @ cipher_matrix
clear_matrix = clear_matrix % len(alphabet)
print('Clear matrix\n')
pprint(sympy.Matrix(clear_matrix))

out = ''
for col in clear_matrix.T:
    charidx = list(col.tolist()[0])
    for idx in charidx:
        out += alphabet[idx]
print(f'Cleartext: {out}')
```

```
Key matrix

⎡16  27  27⎤
⎢          ⎥
⎢25  10  9 ⎥
⎢          ⎥
⎣15  5   27⎦
Cipher matrix

⎡25  23  17  19⎤
⎢              ⎥
⎢23  14  4   11⎥
⎢              ⎥
⎣21  1   14  12⎦
Clear matrix

⎡22  19  4   26⎤
⎢              ⎥
⎢0   28  11  26⎥
⎢              ⎥
⎣13  7   15  26⎦
Cleartext: WANT HELP...
```

### Cracking

We can get the key from a given plain & ciphertext via the cracking theorem. One unknown that has to be infered/guessed is the block size (or matrix dimensions of the key). I tried several and noticed that 6×6 gives a readable result.

```
full_cleartext = ""
full_ciphertext = ""

matrix_dim = 6
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ .,"
cleartext = "THIS NEW ENCRYPTION METHOD IS EXCELL"
ciphertext = "AHTNTRZPBEMVVUGIKBZNEYN,IPAZPWEQZBRO"

clear_array = np.array([alphabet.index(x) for x in cleartext])
while len(clear_array)%matrix_dim != 0:
    last = clear_array[-1]
    clear_array = np.append(clear_array, last)

cipher_array = np.array([alphabet.index(x) for x in ciphertext])
while len(cipher_array)%matrix_dim != 0:
    last = cipher_array[-1]
    cipher_array = np.append(cipher_array, last)
l2 = len(cipher_array)
cipher_array = np.split(cipher_array, len(cipher_array)/matrix_dim)
cipher_matrix = np.matrix(cipher_array).T
print('Cipher matrix\n')
pprint(sympy.Matrix(cipher_matrix))

# pad cleartext to ciphertext len
while len(clear_array) < l2:
    last = clear_array[-1]
    clear_array = np.append(clear_array, last)
clear_array = np.split(clear_array, len(clear_array)/matrix_dim)
clear_matrix = np.matrix(clear_array).T
print('Clear matrix\n')
pprint(sympy.Matrix(clear_matrix))


m3 = np.concatenate((clear_matrix.T, cipher_matrix.T), axis=1)
gl = len(m3)
print('Combined matrix\n')
pprint(sympy.Matrix(m3))
```

```
Cipher matrix

⎡0   25  21  25  8   4 ⎤
⎢                      ⎥
⎢7   15  20  13  15  16⎥
⎢                      ⎥
⎢19  1   6   4   0   25⎥
⎢                      ⎥
⎢13  4   8   24  25  1 ⎥
⎢                      ⎥
⎢19  12  10  13  15  17⎥
⎢                      ⎥
⎣17  21  1   28  22  14⎦
Clear matrix

⎡19  4   17  13  14  4 ⎤
⎢                      ⎥
⎢7   22  24  26  3   23⎥
⎢                      ⎥
⎢8   26  15  12  26  2 ⎥
⎢                      ⎥
⎢18  4   19  4   8   4 ⎥
⎢                      ⎥
⎢26  13  8   19  18  11⎥
⎢                      ⎥
⎣13  2   14  7   26  11⎦
Combined matrix

⎡19  7   8   18  26  13  0   7   19  13  19  17⎤
⎢                                              ⎥
⎢4   22  26  4   13  2   25  15  1   4   12  21⎥
⎢                                              ⎥
⎢17  24  15  19  8   14  21  20  6   8   10  1 ⎥
⎢                                              ⎥
⎢13  26  12  4   19  7   25  13  4   24  13  28⎥
⎢                                              ⎥
⎢14  3   26  8   18  26  8   15  0   25  15  22⎥
⎢                                              ⎥
⎣4   23  2   4   11  11  4   16  25  1   17  14⎦
```

```
def mod(x,modulus):
    numer, denom = x.as_numer_denom()
    return numer*mod_inverse(denom,modulus) % modulus

r = sympy.Matrix(m3).rref()
rr_matrix = (r[0].applyfunc(lambda x: mod(x,len(alphabet))))
print('Row reduced matrix:\n')
pprint(rr_matrix)
```

```
Row reduced matrix:

⎡1  0  0  0  0  0  26  20  6   1   10  10⎤
⎢                                        ⎥
⎢0  1  0  0  0  0  8   26  23  10  10  1 ⎥
⎢                                        ⎥
⎢0  0  1  0  0  0  18  24  5   25  26  12⎥
⎢                                        ⎥
⎢0  0  0  1  0  0  27  3   21  9   14  19⎥
⎢                                        ⎥
⎢0  0  0  0  1  0  25  17  12  2   1   9 ⎥
⎢                                        ⎥
⎣0  0  0  0  0  1  2   7   0   27  11  17⎦
```

```
A = rr_matrix[:,gl:]
A = A.T
print('Recovered decryption key:\n')
pprint(A)

A = np.matrix(A).astype(float)
A = modMatInv(A, len(alphabet)).astype(int)
print('Recovered encryption key:\n')
pprint(sympy.Matrix(A))
```

```
Recovered decryption key:

⎡26  8   18  27  25  2 ⎤
⎢                      ⎥
⎢20  26  24  3   17  7 ⎥
⎢                      ⎥
⎢6   23  5   21  12  0 ⎥
⎢                      ⎥
⎢1   10  25  9   2   27⎥
⎢                      ⎥
⎢10  10  26  14  1   11⎥
⎢                      ⎥
⎣10  1   12  19  9   17⎦
Recovered encryption key:

⎡14  12  12  17  18  23⎤
⎢                      ⎥
⎢15  16  22  25  7   2 ⎥
⎢                      ⎥
⎢2   3   0   11  28  9 ⎥
⎢                      ⎥
⎢7   0   24  6   1   18⎥
⎢                      ⎥
⎢14  8   9   1   27  5 ⎥
⎢                      ⎥
⎣22  1   1   23  5   17⎦
```

### Decrypt with recovered key

```
dec_key_matrix = np.matrix(A)

n = 6*6
ciphertext = "V,CFNOQQOMVBFY, FITGZML BUN,THBM XJPGMKHITAY SNTX,IKXFQKMOJF,QF,DO..SJV LKASFYNV.ZDBPGYDDUWUHIUMW,LQSCTK.KEHIPNG,V"
ciphertext = [ciphertext[i:i+n] for i in range(0, len(ciphertext), n)]

all_out = ''
for i in range(len(ciphertext)):
    # ciphertext to matrix
    cipher_array = np.array([alphabet.index(x) for x in ciphertext[i]])
    # padding
    while len(cipher_array)%matrix_dim != 0:
        last = cipher_array[-1]
        cipher_array = np.append(cipher_array, last)
    cipher_array = np.split(cipher_array, len(cipher_array)/matrix_dim)
    cipher_matrix = np.matrix(cipher_array).T
    print("")
    pprint(sympy.Matrix(cipher_matrix))

    clear_matrix = dec_key_matrix * cipher_matrix
    clear_matrix = clear_matrix % len(alphabet)
    out = ''
    for col in clear_matrix.T:
        charidx = list(col.tolist()[0])
        for idx in charidx:
            out += alphabet[idx]
    all_out += out
print(all_out)
```

```
⎡21  16  5   19  1   1 ⎤
⎢                      ⎥
⎢28  16  24  6   20  12⎥
⎢                      ⎥
⎢2   14  28  25  13  26⎥
⎢                      ⎥
⎢5   12  26  12  28  23⎥
⎢                      ⎥
⎢13  21  5   11  19  9 ⎥
⎢                      ⎥
⎣14  1   8   26  7   15⎦

⎡6   0   23  16  28  27⎤
⎢                      ⎥
⎢12  24  28  10  16  27⎥
⎢                      ⎥
⎢10  26  8   12  5   18⎥
⎢                      ⎥
⎢7   18  10  14  28  9 ⎥
⎢                      ⎥
⎢8   13  23  9   3   21⎥
⎢                      ⎥
⎣19  19  5   5   14  26⎦

⎡11  13  15  22  22  19⎤
⎢                      ⎥
⎢10  21  6   20  28  10⎥
⎢                      ⎥
⎢0   27  24  7   11  27⎥
⎢                      ⎥
⎢18  25  3   8   16  10⎥
⎢                      ⎥
⎢5   3   3   20  18  4 ⎥
⎢                      ⎥
⎣24  1   20  12  2   7 ⎦

⎡8 ⎤
⎢  ⎥
⎢15⎥
⎢  ⎥
⎢13⎥
⎢  ⎥
⎢6 ⎥
⎢  ⎥
⎢28⎥
⎢  ⎥
⎣21⎦
THE FLAG IS SHA TWO FIVE SIX OF LESTER.HILL.WOULD.BE.PROUD.OR.NOT REMEMBER NO NEWLINE, SUBMIT IN NORMAL FORMAT....
```