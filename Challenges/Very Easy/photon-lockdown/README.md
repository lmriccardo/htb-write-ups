# CHALLENGE - PHOTON LOCKDOWN

---

- There are three files `fwu_ver`, `hw_ver` and `rootfs`
- `fwu_ver` contains a value **3.0.5**
- `hw_ver` contains a value **X1**

```bash
$ file rootfs
rootfs: Squashfs filesystem, little endian, version 4.0, 
zlib compressed, 10936182 bytes, 910 inodes, blocksize: 131072 bytes, 
created: Sun Oct  1 07:02:43 2023
```

- Hence `rootfs` is a filesystem, that we can mount 

```bash
$ mkdir tmp
$ sudo mount rootfs ./tmp/
$ cd tmp
tmp$ la -lh

total 0
drwxrwxr-x 3 root root 3.2K Aug 10  2022 bin
lrwxrwxrwx 1 root root   13 Aug 10  2022 config -> ./var/config/
drwxrwxr-x 2 root root 3.1K Aug 10  2022 dev
drwxrwxr-x 7 root root  926 Oct  1  2023 etc
drwxrwxr-x 3 root root   31 Oct  1  2023 home
drwxrwxr-x 2 root root    3 Oct  1  2023 image
drwxrwxr-x 6 root root 2.6K Aug 10  2022 lib
-rw-rw-r-- 1 root root    0 Aug 10  2022 .lstripped
lrwxrwxrwx 1 root root    8 Aug 10  2022 mnt -> /var/mnt
drwxrwxr-x 2 root root    3 Aug 10  2022 overlay
drwxrwxr-x 2 root root    3 Aug 10  2022 proc
drwxrwxr-x 2 root root    3 Aug 10  2022 run
lrwxrwxrwx 1 root root    4 Aug 10  2022 sbin -> /bin
drwxrwxr-x 2 root root    3 Aug 10  2022 sys
lrwxrwxrwx 1 root root    8 Aug 10  2022 tmp -> /var/tmp
drwxrwxr-x 3 root root   28 Aug 10  2022 usr
drwxrwxr-x 2 root root    3 Aug 10  2022 var

tmp$ cd home
tmp$ la -lh

total 0
drwxr-xr-x 2 root root 28 Oct  1  2023 .41fr3d0

tmp/home/$ cd .41fr3d0
tmp/home/.41fr3d0$ ls

s.txt

tmp/home/.41fr3d0$ cat s.txt
almost there
```

- It seems that nothing can found ...
- However, if we try to inspect the entire filesystem

```bash
tmp/$ la -lhR 
```

- We can easily see that there are some files modified on 2023 instead of 2022
- This set of files includes `s.txt` that we have previously found
- Finally, the interesting file is named `./etc/config_default.xml` containing

```xml
...
<Value Name="SYSLOG_MODE" Value="0"/>
<Value Name="SYSLOG_SERVER_IP" Value="0.0.0.0"/>
<Value Name="SYSLOG_SERVER_PORT" Value="0"/>
<Value Name="SUSER_NAME" Value="admin"/>
<Value Name="SUSER_PASSWORD" Value="HTB{N0w_Y0u_C4n_L0g1n}"/>
...
```
