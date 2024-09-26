---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/hzsGMj9C8Nw/0.jpg
layout: post
media_subpath: /assets/posts/2021-11-06-active-directory-reverse-engineering-unintended-solutions-pivotapi-hackthebox
tags:
- active directory
- asreproast
- hackthebox
- kerberoast
- mssql
- seimpersonate
- semanagevolume
- windows
title: Active Directory, Reverse Engineering & Unintended Solutions - Pivotapi
  @ HackTheBox
---

We are solving Pivotapi, a 50-point Windows machine on HackTheBox. This one involves some Reverse Engineering, MSSQL, and Active Directory Attacks like Kerberoasting, ASREPRoasting, and various misconfigurations. At the end, we will explore some unintended ways to root this box.

{% youtube hzsGMj9C8Nw %}

## Notes & Tools

- <https://github.com/zcgonvh/EfsPotato>
- <https://github.com/itm4n/PrintSpoofer>
- <https://github.com/antonioCoco/RoguePotato>
- <https://twitter.com/0gtweet/status/1303427935647531018>
- <https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks>
- <https://github.com/xct/SeManageVolumeAbuse>