---
categories:
- Tools
layout: post
media_subpath: /assets/posts/2019-08-03-release-ropstar
tags:
- binary exploitation
- linux
- rop
- tools
title: 'Release: Ropstar'
---

I encountered a lot of pwn challenges recently, so I decided to automate a lot of it in [ropstar](https://github.com/xct/ropstar). The tool basically solves simple linux bof challenges by using rop chains to bypass nx. It can also handle memory leaks in order to bypass aslr and has basic support for format string attacks. A current list of challenges I tried it on succesfully can be found in the repos readme file, along with further information. This is how it looks:

![asciicast](https://asciinema.org/a/4i9lnxaPirZ6LXygmd1cRQOzT.png)
