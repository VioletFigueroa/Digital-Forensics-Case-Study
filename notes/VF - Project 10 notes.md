---
draft: true
tags: ["notes", "investigation"]
---

1\. Confirm the OS version of the *DC01* server.1. Confirm the OS version of the DC01 server.

Mount the Disk Image

Use FTK Imager to load DC01-E01 as a read-only drive.

Go to \`C:\\Windows\\System32\\config\\SOFTWARE (registry hive)\`

right click and export the shown files, including the .FileSlack and .LOG files

￼

1) Mount the Disk Image

Use FTK Imager to load DC01-E01 as a read-only drive.
Go to \`C:\\Windows\\System32\\config\\SOFTWARE (registry hive)\`
right click and export the shown files, including the .FileSlack and .LOG files

B) Analyze the Registry
Download tool:
[https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip](https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip)
unzip folder
run \`RegistryExplorer.exe\`  as administrator
if prompted, download .NET 9.0 Desktop Runtime (v9.0.4) or higher:
[https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-9.0.4-windows-x64-installer?cid=getdotnetcore](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-9.0.4-windows-x64-installer?cid=getdotnetcore)
File \> Load Hive \> open the \`SOFTWARE\` hive files exported
Go to: \`Microsoft\\Windows NT\\CurrentVersion\`
![Windows Registry ProductName showing Windows Server 2012 R2](/images/projects/project-10/image1.png)
Note the ProductName is Windows Server 2012 R2 Standard Evaluation
3\. Local Time Verification

a) Check Timezone Settings
![Timezone settings in registry](/images/projects/project-10/image2.png)
In the registry hive SYSTEM, navigate to:
text
ControlSet001\\Control\\TimeZoneInformation
![TimeZoneKeyName registry entry showing Pacific Standard Time](/images/projects/project-10/image3.png)
Note the TimeZoneKeyName is Pacific Standard Time. This means the server time is UTC-8 (UTC-7 during daylight savings)

B) Analyze Security Event Logs
Extract C:\\Windows\\System32\\winevt\\Logs\\Security.evtx and
C:\\Windows\\System32\\winevt\\Logs\\System.evtx using FTK Imager.

![Security event logs in Event Viewer](/images/projects/project-10/image4.png)

Right click the security evtx log file and open in Event Viewer Snapin Launcher

Filter for Event ID 4616 to confirm if there has been any system time change.
No Event ID 4616 entries were found in the Security log, confirming that the system clock was not manually changed during the relevant period.
Right click the system evtx log file and open in Event Viewer Snapin Launcher
![System event log showing timezone change on 2020-09-17](/images/projects/project-10/image5.png)
On 2020-09-17 at 9:43:58 AM, a time zone change occurred on the system, as recorded in the System event log (Event ID 1, Kernel-General). This means that from this point forward, all system logs and file timestamps will reflect the new time zone setting. The underlying system time (in UTC) did not change, but the local time displayed by the system and recorded in logs will now be offset according to the new time zone.

6\. Breach Confirmation
Objective: Identify unauthorized access or data exfiltration.
The Security Logs are present in Security.evtx. Since the desktop shows the attack starting at 3:40:49 UTC on the desktop, the corresponding server activity should be at or near this time. The Security.evtx timestamps will be displayed in the server's configured time zone. Given that the event occurred in September 2020 (when daylight saving was active), it is displayed in the logs as PDT (UTC-7). 3:40:49 UTC \= 20:40:49 PDT (previous day).
When we filter for
 Event ID 4624 (successful logon) from unusual IPs (e.g., external addresses).
 Event ID 4672 (privilege escalation) by non-admin users.
We see that

Memory Analysis
Run Volatility’s windows.netscan on DC01-memory.raw:
powershell
volatility \-f DC01-memory.raw windows.netscan
Look for unexpected connections (e.g., 10.42.0.100:443 → 185.xxx.xxx.xxx:8080).
Documentation
Table of suspicious logins:
