---
title: MedusaLocker_Ransomware_Analysis_Report_Fix
date: 2024-3-9
categories: [Malware Analysis , Reports]
tags: [TAG] 
---

> Intro 
> 
# **Index**

1. Malware Basic Static Analysis
2. Malware Basic Dynamic Analysis
3. Static Code Analysis
4. Basic Yara Rule
5. IOCs


## Malware Basic Static Analysis

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_1.png?alt=media&token=c64aced5-1628-4b07-aae8-c1542cbeddc4)

- 62 Vendors Detect the Sample as Malicious.
- First, I checked whether the sample is packed or not, and it is not packed.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_18.png?alt=media&token=cd09041e-29cf-4bc5-bae3-eea8e3f41382)

- I then looked for the imports. There are 189 imports. We will analyze them in IDA.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_19.png?alt=media&token=12e36387-8722-4c1f-b6ed-4fee2169e3ba)

    > file-size,685568 bytes
    > signature,Microsoft Visual C++
    > compiler-stamp,Thu Oct 31 06:08:40 2019
    > cpu,32-bit
![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_21.png?alt=media&token=85c7824b-c2a2-45c7-bc1b-3373ede6b9e9)

----
## Malware Basic Dynamic Analysis

- Let's open Procexp and Fakenet-ng to check for any processes and network connectivity.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_22.png?alt=media&token=f21c4c5f-638d-4087-ba9d-dbb6e0746699)

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_10.png?alt=media&token=63ebb14c-df2d-4c04-8cb6-b620b18c46d9)



![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_24.png?alt=media&token=3ea1505e-0b98-4fa2-bacc-a8dcb6883934)

- We've detected svchost.exe, indicating that the malware attempts to persist through the Task Scheduler. Additionally, there is a task set to repeat every 15 minutes to ensure the malware's persistence.

- Moreover, there is an HTML file executed after running the sample.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_12.png?alt=media&token=7264289c-3f15-49e3-b5f3-28bf17260d9b)

- The ransomware note contains two email addresses for communication.

1. rdp_unlock@outlook[.]com
2. rdpunlock@cock[.]li

----
## Static Code Analysis

- I found this mutex code: **“8761ABBD-7F85-42EE-B272-A76179687C63”**. The malware utilizes mutex to ensure that the sample runs only once.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_26.png?alt=media&token=a531e8e0-c74d-4284-bccd-f5d3acec06f5)

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_27.png?alt=media&token=9df76ac2-6524-414d-99cd-8a17621fa01a)

    > Registry Key “SOFTWARE\\MDSLK”
![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_8.png?alt=media&token=0fdf25f2-b4f3-4653-b76b-12d9d87f6af5)

    > CopyFileW 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_28.png?alt=media&token=b4dfee4d-c776-4d80-9fe0-9f73fd09f477)


    > sleep 
    CHATGPT: In summary, the sub_41ED00 function is responsible for managing Windows services, including querying status, controlling service state, and handling delays.
    Medusa When See Those Services Sleep
![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_29.png?alt=media&token=cb6aa68c-eae9-429f-9865-05cfeae4a1c9)

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot_30.png?alt=media&token=c04f5bd4-3bb3-4c35-878c-cff16e4043f6)



---
## Yara 

```m
rule Medusa
{

    strings: 
        $md5 = "762eaa081c9f641aba9ab75b7ae6ee09"
        $sha1 = "97f2ba64780efd18943e2cfd67f18df90e0bf39a"
        $sha256 = "36baceccfe27fb8b1be3d4f0a9e81b9028640aeedf068d71b3a6d080e698a793"
        $Is_running = "[LOCKER] Is running"
        $registry_key =  "MDSLK"
        $mutex = "8761ABBD-7F85-42EE-B272-A76179687C63"
        $domain1 = "rdp_unlock@outlook.com"
        $domain2 = "rdpunlock@cock.li"
    condition:
        any of them
}
```

----
## IOCs

    > 
    
    hashes :
    md5: 762eaa081c9f641aba9ab75b7ae6ee09
    sha1: 97f2ba64780efd18943e2cfd67f18df90e0bf39a
    sha256: 36baceccfe27fb8b1be3d4f0a9e81b9028640aeedf068d71b3a6d080e698a793

    Emails: 
        1. rdp_unlock@outlook[.]com
        2. rdpunlock@cock[.]li

    mutex: 
        "8761ABBD-7F85–42EE-B272-A76179687c63"