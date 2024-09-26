---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/ZnUIiVwNSHk/0.jpg
layout: post
media_subpath: /assets/posts/2021-04-10-apt-hackthebox
tags:
- hackthebox
- ipv6
- msrpc
- registry
- responder
- secretsdump
- windows
title: APT @ HackTheBox
---

APT is a 50-point machine on HackTheBox which involves getting the IPv6 Address via MS-RPC, credential spraying, and reading the boxes registry remotely. For root, we force authentication of the box’s machine account to our box, capture it with responder, crack it, and then use secretsdump to obtain the administrator hash.

{% youtube ZnUIiVwNSHk %}