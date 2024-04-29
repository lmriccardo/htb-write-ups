# MACHINE - HEIST

---

## OPEN PORTS

```bash
$ nmap -sVC -T4 -Pn {IP}

80/tcp  open  http          Microsoft IIS httpd 10.0
| http-title: Support Login Page
|_Requested resource was login.php
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp open  msrpc         Microsoft Windows RPC
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

---

## INVESTIGATING THE SITE

- Source code ... Nothing special
- One cookie is set

```
PHPSESSID=du6i87ic2q6gl155s92h5qdln1
```

- Wappalyzer found the following interesting result

1. IIS Web Server Version 10.0

> *Microsoft Internet Information Services* (IIS, 2S) is an extensible web server created 
> by Microsoft for use with the Windows NT family. IIS supports HTTP, HTTP/2, HTTP/3, 
> HTTPS, FTP, FTPS, SMTP and NNTP. It has been an integral part of the Windows NT family 
> since Windows NT 4.0, though it may be absent from some editions (e.g. Windows XP Home 
> edition), and is not active by default.

- At this point let's enumerate all directories using gobuster

```bash
$ gobuster dir -u http://{IP}/ -w /usr/share/wordlists/dirb/common.txt

...
/attachments          (Status: 301) [Size: 158]
/css                  (Status: 301) [Size: 150]
/Images               (Status: 301) [Size: 153]
/images               (Status: 301) [Size: 153]
/index.php            (Status: 302) [Size: 0]
/js                   (Status: 301) [Size: 149]
...
```

- Trying to access all the pages, except for `index.php`, lead to `Access denied`
- Before trying to bruteforce the login we see a button `Login as guest`
- If we click on that button we go to a new page `issues.php`
- There are a bunch of messages with an `Attachment`
- If we open the attachment we can see a lot of useful informations
- Then a number of configurations

```
...
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
...
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
...
ip ssh authentication-retries 5
ip ssh version 2
...
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh
```

- As we can see there are some usernames and passwords I guess
- An SSH authentication system configuration
- 

---

## FLAGS

