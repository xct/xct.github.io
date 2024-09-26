---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/OG_wJNu9zGk/0.jpg
layout: post
media_subpath: /assets/posts/2020-06-13-monteverde-hackthebox
tags:
- active directory
- azure ad
- hackthebox
- ldap
- smb
- windows
title: Monteverde @ HackTheBox
---

Monteverde is a 30-point Windows machine on HackTheBox that involves some LDAP and SMB enumeration to get the user flag. For root we exploit Azure AD Connect’s way of storing the password for the account that synchronizes on premise AD accounts with Azure AD.

{% youtube OG_wJNu9zGk %}