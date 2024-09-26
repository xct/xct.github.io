---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-08-03-safe-hackthebox
tags:
- binary exploitation
- hackthebox
- keepass
- linux
title: Safe @ HackTheBox
---

Safe is an "easy" machine on hackthebox, involving a simple buffer overflow and cracking a keepass file.

## User Flag

We use [ropstar](https://github.com/xct/ropstar), get a shell and the user flag.

## Root Flag

Using keepass2john we generate a hash file for every image:

```
keepass2john -k <img> MyPasswords.kdbx > hash
```

We run rockyou-75.txt against it and find the password "bullshit" rather quickly. Inside the keepass file we find roots password "u3v2249dl9ptv465cogl3cnpo3fyhk". Now we add our ssh key to "user", ssh into the box and su to root.