---
title: QRadar_Community_Edition_Installation
date: 2025-02-26
categories: [SOC Engineering]
tags: [TAG]     # TAG names should always be lowercase
---

# **Introduction**  

IBM QRadar Community Edition (CE) is a powerful SIEM tool for threat detection, log analysis, and security monitoring. This guide provides a step-by-step walkthrough on installing QRadar Community Edition on VMware, including key configurations and troubleshooting tips. Let’s dive in!

## Step 1: Download the Qradar Community Edition ISO

1. Visit the official IBM QRadar Community Edition page:
    
    - https://www.ibm.com/community/101/qradar/ce/

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_3.png?alt=media&token=af8589fb-d162-476f-ab8e-8bb550420065)
        
1. Ensure that you download the correct ISO file:
    
    - Verify the file integrity to confirm it is the official IBM release.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_5.png?alt=media&token=63bb00f1-49ef-4e57-bcda-c5994fa272b0)

## Step 2: Import the ISO into VMware

### Configure VMware Virtual Machine

1. **CPU Configuration:**
    
    - Minimum: 4 cores
        
    - Recommended: More for better performance

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_6.png?alt=media&token=be7dfd64-0a06-4f94-b6cd-a48839c89dde)

- **RAM Allocation:**
    
    - Minimum: 24 GB RAM 


![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_7.png?alt=media&token=4835f6d5-263e-4fef-9192-7ba4c9daebb4)

1. **Storage Configuration:**
    
    - Select **SATA** for improved performance
        
    - Pre-allocate a minimum of **250 GB** and choose **one file** for the virtual disk.
        
> **Thin Provisioning Explained:** Thin provisioning allows the VM to allocate only the disk space that is actively being used, rather than reserving the entire disk size upfront. However, QRadar requires the full allocated space for proper functionality.

> **Note:** The pre-allocation process may take some time—be patient!


![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_8.png?alt=media&token=71cc52c3-e6e8-48af-bfda-797f0501a4b1)


## Step 3: Configure BIOS Settings in VMware

If you encounter issues with booting, switch to **UEFI mode**:

- Go to **VMware Machine Settings** → **Options** → **Advanced** → **UEFI**.


![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_10.png?alt=media&token=89b4a39f-42d4-4c5b-81cd-c976fb36d7e8)

## Step 4: Start the Installation

1. Boot from the ISO file.
    
2. Select the first option to begin the installation.
    
3. The process may take some time, so be patient.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_11.png?alt=media&token=3fa2dbf3-9635-4760-af9b-74ac38e70c6c)

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_30.png?alt=media&token=d9601618-620f-46f3-a743-ea1c9f378688)

## Step 5: Initial Setup and Configuration

- **Login as** `root`

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_15.png?alt=media&token=f1e7d4a6-75cb-4c9d-aabe-d84a1e267e11)


- **Accept the License Agreement**:
    
    - Press **space** to scroll down and type `yes` to accept.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_17.png?alt=media&token=c3c725be-4bf6-4dee-8d93-c76f1cd23117)

- **Select the Installation Option**:
    
    - Choose the **second option** and confirm with default settings.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_18.png?alt=media&token=19a3388a-36da-4146-a077-06e445b36117)

- and press ok o all with default 

- **Set Network Configurations**:
    
    - Assign **IP address**, **hostname**, and **DNS settings**.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_29.png?alt=media&token=646eaa9d-dce7-459e-a085-f023067c7acd)

- Enter Complex Password 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_21.png?alt=media&token=71a69428-d110-4a3e-8400-d8822c70b248)

> Note: The initial boot and indexing process may take some time. Allow the system to stabilize before proceeding with configurations.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_31.png?alt=media&token=3dd4e028-b19f-4909-9945-f417f7d53141)


![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_26.png?alt=media&token=affd5e57-99f3-49b7-9620-76805528c195)

## Step 6: Access QRadar

- Open a web browser and enter the assigned IP address.
    
- Log in with your **admin** credentials.
    
- Start configuring Qradar for log collection and security analysis.

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_32.png?alt=media&token=ac02271c-13a3-45ee-9831-374d704bc51a)

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/sf%2FScreenshot_35.png?alt=media&token=b7817a24-17ec-48a0-af19-af5dcb320f44)

