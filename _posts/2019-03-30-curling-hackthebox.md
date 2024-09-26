---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-03-30-curling-hackthebox
tags:
- hackthebox
- joomla
- linux
- obfuscation
title: Curling @ HackTheBox
---

Curling is one of the easier boxes on [hackthebox.eu](https://www.hackthebox.eu), featuring getting a shell on joomla via template editing, getting a password from an obfuscated file and exploiting an insecure curl script.

## User Flag

We start by looking at port 80 and find a joomla based website called "Cewl Curling Site". Looking at source we see a hint at a file called "secret.txt", which contains a base64 string that decodes to the following:

```
Curling2018!
```

There are some posts on the website that have "Floris" as author, so we try to log into the application as "Floris:Curling2018!" which succeeds. Since we want to get to admin panel we log into "/administrator" and get to the joomla backend.

We can execute php code by editing the currently active templates "error.php". In order got get a shell we replace its contents with a [php reverse shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and get a connection back.

In the home folder of Floris we find a password backup file called "password\_backup", which we download via nc to our box and analyze. It seems to be the output of the tool "xxd" on some binary file:

```
tmp cat password_backup
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
```

We remove the output around the bytes and convert it to binary, followed by a couple of extractions to get the contents:

```
cat password_backup | cut -d " " -f 2-9 | sed -e 's/ //g' | sed -e ':a;N;$!ba;s/\n//g' | xxd -r -p > out
out: bzip2 compressed data, block size = 900k

bzip2 -d out
file out.out
out.out: gzip compressed data, was "password", last modified: Tue May 22 19:16:20 2018, from Unix, original size 141

binwalk -e out.out
...
cat 18
password.txt0000644000000000000000000000002313301066143012147 0ustar  rootroot5d<wdCbdZu)|hChXll
```

This looks like a password (`5d<wdCbdZu)|hChXll`) so we try to use it to ssh into the box as Floris and can read the user flag.

## Root Flag

Floris has a folder called "admin-area" in his home folder which contains two files called input and report, report being the source of the website we saw earlier and input looking like this:

```
url = "http:/127.0.0.1"
```

This suggests that the url in "input" is being used as a target for curl and that the output is being redirected to "report". We are able to read the root flag from "report" by changing input to point to it:

```
echo 'url = "file:///root/root.txt"' > input
wc -c report
33 report
```

Thanks to [L4mpje](https://www.hackthebox.eu/home/users/profile/29267) for creating this fun box.