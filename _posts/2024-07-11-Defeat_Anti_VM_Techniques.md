---
title: Defeat_Anti_VM_Techniques
date: 2024-07-11
categories: [Malware Techniques]
tags: [TAG]     # TAG names should always be lowercase
---

## Don't  Forget  To Modify The  Path In The Script & Values If You Want  

```powershell
$keysToRemove = @(
    "HKLM:\SYSTEM\ControlSet001\Control\SystemInformation",
    "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"
)

function Remove-RegistryKeys {
    foreach ($key in $keysToRemove) {
        if (Test-Path $key) {
            Remove-Item -Path $key -Force -Recurse
        }
    }
}

$serviceName = "VMTools"
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force
    Set-Service -Name $serviceName -StartupType Disabled
}

Remove-RegistryKeys

# Put The Path Where Youu Saved The Script 
$scriptPath = ""

$scriptContent = @'
while ($true) {
    
    $keysToRemove = @(
        "HKLM:\SYSTEM\ControlSet001\Control\SystemInformation",
        "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"
    )

    foreach ($key in $keysToRemove) {
        if (Test-Path $key) {
            Remove-Item -Path $key -Force -Recurse
        }
    }

    Start-Sleep -Seconds 60
}
'@

Set-Content -Path $scriptPath -Value $scriptContent

$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -StartWhenAvailable

Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -TaskName "ContinuousRemoveRegistryKeys" -Description "Continuously remove specific registry keys at startup"

$files = @(
    "C:\Windows\System32\drivers\vmci.sys",
    "C:\Windows\System32\drivers\vmhgfs.sys",
    "C:\Windows\System32\drivers\vmmemctl.sys",
    "C:\Windows\System32\drivers\vmrawdsk.sys"
)

$newNames = @("test1.sys", "test2.sys", "test3.sys", "test4.sys")

for ($i = 0; $i -lt $files.Length; $i++) {
    Rename-Item -Path $files[$i] -NewName $newNames[$i]

}

# This Will Remove The VMTools 

Rename-Item -Path "C:\Program Files\VMware" -NewName "C:\Program Files\test123" -Force

# Change Ethernet0 with your Ethernet and the mac if you want new one 

Set-NetAdapter -Name "Ethernet0" -MacAddress "3C:D9:2B:8A:3F:10"
```