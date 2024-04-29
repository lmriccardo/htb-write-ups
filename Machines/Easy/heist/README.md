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

---

## FLAGS

