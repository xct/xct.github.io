---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-05-25-luke-hackthebox
tags:
- ajanti
- hackthebox
- linux
- node
title: Luke @ HackTheBox
---

Luke is a rather short, easy machine on hackthebox, which was nonetheless fun to solve and our team got both first bloods here.

## User & Root Flag

We start with a quick tcp port scan and see the following open ports:

```
21/tcp   open  ftp     vsftpd 3.0.3+ (ext.1)
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0             512 Apr 14 12:35 webapp
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.16.46
|      Logged in as ftp
|      TYPE: ASCII
|      No session upload bandwidth limit
|      No session download bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3+ (ext.1) - secure, fast, stable
|_End of status
22/tcp   open  ssh?
| ssh-hostkey:
|   2048 6b:14:c2:13:8f:58:8e:29:ca:c4:19:83:fc:2f:f1:ad (RSA)
|   256 a3:85:67:47:26:f4:67:b0:e1:d5:9f:98:5e:c9:c2:53 (ECDSA)
|_  256 48:3f:98:4e:ea:ed:2b:d2:2f:4d:0b:ea:8b:2c:21:dc (ED25519)
80/tcp   open  http    Apache httpd 2.4.38 ((FreeBSD) PHP/7.3.3)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.38 (FreeBSD) PHP/7.3.3
|_http-title: Luke
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
8000/tcp open  http    Ajenti http control panel
|_http-title: Ajenti
```

There is a web page on port 80, an ajenti web application on port 8000 and a mysterious node.js application on port 3000. Also we have ftp, which we try to login first. Since it accepts anonymous connections, we can get in and grab a hint that was left for us:

```
Dear Chihiro !!

As you told me that you wanted to learn Web Development and Frontend, I can give you a little push by showing the sources of
the actual website I've created .
Normally you should know where to look but hurry up because I will delete them soon because of our security policies !

Derry
```

We start running gobuster against all 3 web ports and browse a bit around manually while waiting for results. The most promising application for the initial foothold seems to be the node.js application on port 3000. We fuzz the application for entry points:

```
wfuzz --hc 404 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-words.txt http://10.10.10.137:3000/FUZZ
...
000009:  C=200      0 L           2 W       13 Ch    "login"
000205:  C=200      0 L           5 W       56 Ch    "users"
...
```

On "/" and "/users" we are told, that we miss an authorization token and on "/login" it says "please auth". We do not have any credentials yet to auth with but this will be important later on.

Meanwhile gobuster has found some interesting files: on port 80 we have a config.php with the following contents:

```
/config.php (Status: 200)
$dbHost = 'localhost'; $dbUsername = 'root'; $dbPassword = 'Zk6heYCyv6ZE9Xcg'; $db = "login"; $conn = new mysqli($dbHost, $dbUsername, $dbPassword,$db) or die("Connect failed: %s\n". $conn -> error); 
```

With this password, we can now try to play with the node.js application again. We try a few usernames and finally log into the application as "admin":

![](htb_luke_nodejslogin.png)

One thing to watch out for here is to set the content type to "application/json" – if you don’t do that you will get "400 Bad Request". We set the Authorization header to the token we just obtained and query the users endpoint we saw earlier to get the following output:

```
/users

[{"ID":"1","name":"Admin","Role":"Superuser"},{"ID":"2","name":"Derry","Role":"Web Admin"},{"ID":"3","name":"Yuri","Role":"Beta Tester"},{"ID":"4","name":"Dory","Role":"Supporter"}]
```

We can now retrieve more detailed information about every user:

```
/users/<username>

{"name":"Admin","password":"WX5b7)>/rp$U)FW"}
{"name":"Derry","password":"rZ86wwLvx7jUxtch"}
{"name":"Yuri","password":"bet@tester87"}
{"name":"Dory","password":"5y:!xa=ybfe)/QD"}
```

After some trial and error we log into the app on port 80 on "/management" as Derry with the password we just acquired. We get a directory listing, showing a file called "config.json" with the following (heavily shortened) output:

```
...
"{\"projects\": \"KGxwMQou\\n\"}"
password    "KpMasng6S5EtTy9Z"
```

With this new password we can now log into the ajenti app on port 8000 as "root". For me this did not load properly on firefox and chromium on my linux vm, so I had to use my windows 10 vm for ajanti to finally load up. We can now just start a terminal and read both flags, as we are root.

Many thanks to [h4d3s](https://twitter.com/@h4d3s99) for creating the box.