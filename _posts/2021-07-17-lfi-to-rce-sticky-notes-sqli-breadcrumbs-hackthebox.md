---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/ULEHr2tfkmk/0.jpg
layout: post
media_subpath: /assets/posts/2021-07-17-lfi-to-rce-sticky-notes-sqli-breadcrumbs-hackthebox
tags:
- cookies
- hackthebox
- jwt
- lfi
- sql injection
- sticky notes
- windows
title: LFI to RCE, Sticky Notes & SQLi - Breadcrumbs @ HackTheBox
---

We are solving Breadcrumbs, a 40-point Windows machine on HackTheBox. For user, we exploit an LFI to read PHP source code, forge a session cookie & upload a PHP shell. Root involves dumping sticky notes content & exploiting a SQL injection.

{% youtube ULEHr2tfkmk %}