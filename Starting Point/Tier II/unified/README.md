# MACHINE - UNIFIED

IP: 10.129.96.149

Type: Linux

---

## OPEN PORTS

```bash
$ nmap -sVC -T4 -Pn -p- {IP}
```

- [1] 22/tcp ssh **OpenSSH 8.2p1**
- [2] 6789/tcp ibm-db2-admin?
- [3] 8080/tcp http-proxy

1. Might be redirecting requests
2. Did not follow redirect to http://{IP}:8443/manage

- [4] 8443/tcp ssl/nagios-nsca **Nagios NSCA**

1. Requested resource was `/manage/account/login?redirect=%2Fmanage`

---

## OPENING THE SITE

- Opening `http://{IP}:8080/` being redirected to `http://{IP}:8443/manage/account/login?...`
- Found software named **UniFi 6.4.54** (JAVA backend)

> *UniFi* is a community of wireless access points, switches, routers, controller devices, 
> VoIP phones, and access control products. It can be used for the corporate network and 
> also for the home network. An Unifi network controller manages all the equipment in the 
> UNIFI network.

- There is a CVE [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) releated to UniFi
- The vulnerability is a *Log4J Remote Code Execution*

> 

---

## FLAGS

USER: 

ROOT: 