---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/ZXymNNk_HI0/0.jpg
layout: post
media_subpath: /assets/posts/2021-09-04-command-injection-prototype-pollution-kubernetes-unobtainium-hackthebox
tags:
- command injection
- electron
- hackthebox
- kubernetes
- linux
- prototype pollution
title: Command Injection, Prototype Pollution & Kubernetes - Unobtainium
  @ HackTheBox
---

This video is about Unobtainium, a 40-point Linux machine on HackTheBox. For user, we download an electron app and proxy it through burp to find some credentials, which we can then use on an API endpoint. Combining a command injection & prototype pollution will then lead to a first shell on a container. For root, we pivot onto a development container & use a token we find there to query Kubernetes for secrets. This leads to an admin token which we can use to spawn a privileged container & then escape it by mounting the host filesystem

{% youtube ZXymNNk_HI0 %}

## Resources

- <https://www.cyberark.com/resources/threat-research-blog/kubernetes-pentest-methodology-part-1>
- <https://github.com/Kirill89/prototype-pollution-explained>
- Machine Author: [https://twitter.com/\_felamos](https://twitter.com/_felamos)