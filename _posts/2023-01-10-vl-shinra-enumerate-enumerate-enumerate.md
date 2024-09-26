---
categories:
- Vulnlab
image:
  path: https://img.youtube.com/vi/9EjXPJ1mweg/0.jpg
layout: post
media_subpath: /assets/posts/2023-01-10-vl-shinra-enumerate-enumerate-enumerate
tags:
- active directory
- linux
- windows
title: VL Shinra Part 2 - Enumerate, Enumerate, Enumerate!
---

This is the second video of the Shinra series. Before setting foot onto any of the network’s internal machines, we are going to spend a bit of time enumerating various things from our machine.

{% youtube 9EjXPJ1mweg %}

Some ideas for further steps that are not shown in the video:

- Spray "Shinra2022" or variations of it against all users in the domain.
- Place a hash grabbing payload (e.g. <https://github.com/xct/hashgrab>) inside the workspace share and see if you can find any hashes.

## Notes

**Tools**

- <https://github.com/ly4k/Certipy>
- <https://github.com/iphelix/dnschef>
- <https://github.com/fox-it/BloodHound.py>
- <https://github.com/Porchetta-Industries/CrackMapExec>

**Tcpdump**

```
tcpdump -i ens37 -s 0 -w - -U | tee output.pcap | tcpdump -r -
```

**Credential spraying**

```terminal
crackmapexec smb 172.16.11.10 -u user.txt -p pass.txt --no-bruteforce --continue-on-success
```

**Bloodhound**

```terminal
sudo sh -c 'proxychains python3 /home/xct/tools/dnschef/dnschef.py --fakeip 172.16.11.101 --fakedomains shinra-dev.vl -q'

proxychains bloodhound-python -c all --disable-pooling -w 1 -u "william.davis" -p 'password' -d shinra-dev.vl -dc dc.shinra-dev.vl -ns 127.0.0.1
```

**Shares**

```terminal
crackmapexec smb 172.16.11.3-254 -u "william.davis" -p 'password' --shares
```

**SMB Signing**

```terminal
crackmapexec smb 172.16.11.3-254 --gen-relay-list relay.txt
```

**Machine Account Quota**

```terminal
crackmapexec ldap 172.16.11.101 -u "william.davis" -p 'password' -M maq
```

**ADCS**

```terminal
crackmapexec ldap 172.16.11.101 -u "william.davis" -p 'password' -M adcs
crackmapexec ldap 172.16.11.101 -u "william.davis" -p 'password' -M adcs -o SERVER=shinra-dev-CA
certipy find -u "william.davis" -p 'password' -dc-ip 172.16.11.101 
```