---
draft: true
tags: ["notes", "investigation"]
---

1. ~~What’s the Operating System of the Server?~~
2. What’s the Operating System of the Desktop?
   * Windows 10
3. ~~What was the local time of the Server?~~
4. Was there a breach?
   * Yes. Malware was found on the Desktop machine and evidence suggests it should be found on server too
5. What was the initial entry vector (how did they get in)?
   * Brute force attack on Server machine to access its Remote Desktop Protocol
6. Was malware used? If so, what was it? If there was malware answer the following:
   * What process was malicious?
     * Coreupdater.exe
     * Spoolsv.exe and powershell.exe were later used to obfuscate malware’s continued presence through injected code
   * Identify the IP Address that delivered the payload.
     * 194.61.24.102
   * What IP Address is the malware calling to?
     * 203.78.103.109
   * Where is this malware on disk?
     * c:\\windows\\system32\\coreupdater.exe
   * When did it first appear?
     * 3:40:49 UTC (time when coreupdater.exe process begins)
   * Did someone move it?
     * Yes. It would have initially been in the Administrator user’s downloads, but eventually moves to System32
   * What were the capabilities of this malware?
     * Malware was capable of reading software policies for system information, encoding using XOR to obfuscate its activity within legitimate processes, manipulating the Windows Registry autorun configuration to enable persistence, and communicating with a C2C server through HTML protocol
   * Is this malware easily obtained?
     * Yes, as it uses the Metasploit framework which MITRE acknowledges as being easily obtained
   * Was this malware installed with persistence on any machine?
     * When?
       1. 3:40:49 UTC (time when coreupdater.exe process begins)
     * Where?
       1. Windows Registry for Desktop machine

**WINDOWS.INFO**
![Windows Registry value showing ProductName as Windows Server 2012 R2 Standard Evaluation](/images/projects/stolen-szechuan-sauce/image1.png)
Noteworthy details

* OS desktop version
  * Layer\_name 0 **WindowsIntel32e**
  * PE MajorOperatingSystemVersion **10**
* Volatility identifies OS version as **Windows 10**

**WINDOWS.PSLIST**
**![System event log showing significant security-related activity during forensic analysis](/images/projects/stolen-szechuan-sauce/image2.png)**
**![Additional forensic evidence showing system configuration changes during attack](/images/projects/stolen-szechuan-sauce/image3.png)**
Noteworthy details

* Unusual process: coreupdate.exe with PID 8324
* A google search reveals **coreupdater.exe** **is not recognized as a typical windows process**. In fact, the process name is associated with the hash for a malicious file on VirusTotal

![Security log entries documenting attack progression and attacker actions](/images/projects/stolen-szechuan-sauce/image4.png)

* VirusTotal states this malware is associated with IP 203.78.103.109
* Parent process with PPID 4008 is not listed and is presumably no longer running, which is unusual behavior

**WINDOWS.PROCDUMP**
![Network forensics results showing traffic patterns from compromised system](/images/projects/stolen-szechuan-sauce/image5.png)
Noteworthy details

* Procdump **fails to generate file** for coreupdater.exe

**WINDOWS.CMDLINE**
**![Log analysis showing system events relevant to incident timeline reconstruction](/images/projects/stolen-szechuan-sauce/image6.png)**
![Detailed attack chain visualization showing attacker progression through network](/images/projects/stolen-szechuan-sauce/image7.png)
Noteworthy details

* Investigating coreupdater.exe further, it seems the **process was exited** by the time the image of the desktop was generated
* Explains why procdump does not generate results when attempting to export the file from the image

**WINDOWS.NETSTAT**
**![Failed login attempts displayed in Event Viewer showing brute force activity](/images/projects/stolen-szechuan-sauce/image8.png)**
Noteworthy details

* A foreign address establishes a connection with the desktop twice, each time to a different port
  * ForeignAddr \- **203.78.103.109 port 443**
  * LocalPorts \- 50875 & 50972
  * Good time to confirm that Desktop’s IP is 10.42.85.115
* Furthermore, the IP is associated with malicious activity on VirusTotal

![Multiple security events showing coordinated failed authentication attempts on systems](/images/projects/stolen-szechuan-sauce/image9.png)

* This IP is also associated with coreupdater.exe on VirusTotal, further suggesting that it is the malicious process on the machine

**WINDOWS.MALFIND**
![Security event logs showing multiple failed authentication attempts and lateral movement indicators](/images/projects/stolen-szechuan-sauce/image10.png)
![Wireshark packet capture showing network traffic analysis for incident investigation](/images/projects/stolen-szechuan-sauce/image11.png)
Noteworthy details

* Both these processes demonstrate assembly code patterns associated with injected code
  * Add byte ptr \[rax\], al \-\> byte ptr \[rax \+ rax\], al \-\> byte ptr \[rax\], al is an example of a “code sandwich” that implies functional code where there shouldn’t be any (<https://dfirmadness.com/case-001-memory-analysis/>)
* Their hex dump also contains certain patterns that suggests it has been modified
  * **MZ \-** frequently associated with malicious injections (<https://dfirmadness.com/case-001-memory-analysis/>)
* Both processes are normally legitimate parts of the Windows ecosystem, further suggesting they’ve been manipulated in some way
* Given that coreupdater.exe was no longer an ongoing process when the image of the desktop was taken, this would explain how it continued to impact the machine

**AUTORUN FILES**
We discovered the following line the in the Desktop’s extracted autorun configuration while investigating the suspicious processes discovered during the memory analysis of the desktop machine: coreupdater.exe, spoolsv.exe and powershell.exe

* 4/14/2010 3:06 PM, "HKLM\\System\\CurrentControlSet\\Services","coreupdater",enabled,"Services",System-wide, "coreupdater:",,"","c:\\windows\\system32\\coreupdater.exe",,"C:\\Windows\\System32\\coreupdater.exe",EED41B4500E473F97C50C7385EF5E374,FD153C66386CA93EC9993D66A84D6F0D129A3A5C,C3E46C6242056ACE3217A5314CFF2063BE8E9799,88763E60ED00AFDA80A61647782B597542D9667D2B9A35FB2623967E302FA28E,10F3B92002BB98467334161CF85D0B1730851F9256F83C27DB125E9A0C1CFDA6,B4C6FFF030479AA3B12625BE67BF4914
  * Note the absence of an explanation for what this process does compared to the comments left for typical elements of a Windows autorun configuration file ie.
    * 3/4/1918 2:18 AM,"HKLM\\System\\CurrentControlSet\\Services","Spooler",enabled,"Services",System-wide,"**Print Spooler: This service spools print jobs and handles interaction with the printer.  If you turn off this service, you won’t be able to print or see your printers.**","(Verified) Microsoft Windows","Microsoft Corporation”...
  * Proof of **persistence tactics** employed through admin level permissions on the desktop machine
  * Also informs us as to final location where coreupdater.exe resided before presumably being deleted to obfuscate malware presence
* 10/23/1937 2:43 AM,"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","coreupdate",enabled,"Logon",System-wide,"Windows PowerShell","(Verified) Microsoft Windows","Microsoft Corporation","c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",10.0.19041.1,"%COMSPEC% /b /c start /b /min powershell \-nop \-w hidden \-c ""sleep 0; iex(\[System.Text.Encoding\]::Unicode.GetString(\[System.Convert\]::FromBase64String((Get-Item 'HKLM:Software\\q9Z1bssi').GetValue('JqxNhWJA'))))""",F8278DB78BE164632C57002E82B07813,EC824EE03F969721AEF5AC2A7D5897D5D150CB13,1BFAA53D93096E0CAC7E940223AD2E139904D154,C662D1FEFB28E81C4ECE143AFC2D329E969BED12F24FE261260F2F7C3144318C,9AF8A2D9CA5D904B9CA6696016B2A794EF7EB97693CCCA22DF2A367305D31B88,7C955A0ABC747F57CCC4324480737EF7
  * Suspicious call for Powershell in the autorun configuration which clearly uses code encoded in base-64
  * Note the keywords **Logon** and **Enabled,** both of which further indicate attackers relied on registry manipulation for persistence tactics by creating configuration where malware would run when user accessed the machine

**PCAP ANALYSIS**
![Process execution logs showing suspicious executable files and their command-line parameters](/images/projects/stolen-szechuan-sauce/image12.png)
Noteworthy details of filtering for traffic to and from IP 203.78.103.109

* Confirm that malicious IP address communicated with desktop machine as well as machine with IP 10.42.85.10
  * Presumably the server, suggesting both are infected with the same malware

![Event logs showing remote desktop connection attempts to the compromised system](/images/projects/stolen-szechuan-sauce/image13.png)
Interesting details

* HTTP requests which eventually results in Desktop machine infection recorded
* Involves IP 194.61.24.102
  * The source of the malware, whereas our other IP IoC is the location of the C2C server

![HTTP traffic logs showing requests to command and control server during compromise](/images/projects/stolen-szechuan-sauce/image14.png)

* Server downloading malware before the desktop does (presumably one led to the other)

![IP indicator of compromise showing location of identified C2C command server](/images/projects/stolen-szechuan-sauce/image15.png)

* IP 194.61.24.102 pings 10.42.85.10 (server) before attempting to connect using multiple different ports to port 3389, the port for Windows Remote Desktop
  * Nmap scan into brute force attack on the port that would grant attacker control over the server

![RDP port 3389 connection attempts showing attacker reconnaissance and lateral movement](/images/projects/stolen-szechuan-sauce/image16.png)

* IP 194.61.24.102 repeatedly attempts to establish HTTP connection on port 80
  * Brute forcing HTTP connection to deliver malware

![Authentication failure logs showing brute force attack attempts on server systems](/images/projects/stolen-szechuan-sauce/image17.png)
![Security audit logs displaying privilege escalation attempts and system access events](/images/projects/stolen-szechuan-sauce/image18.png)

* Example of successful brute force attack on remote desktop protocol
  * Note the cookie detailing that the account being targeted is the administrator \- this reveals both which account ends up downloading the malware and how the attackers gain elevated permissions that allow for their persistence tactics later  on
  * Timestamp for successful bruteforce: Sept 19, 2020 02:56:03 UTC

**DESKTOP IMAGE ANALYSIS**
 **![Event logs showing evidence of data exfiltration and file access during incident](/images/projects/stolen-szechuan-sauce/image19.png)**
Interesting details

* $130 is evidence of deleted or overwritten files ([https://www.sans.org/blog/ntfs-i30-index-attributes-evidence-of-deleted-and-overwritten-files/](https://www.sans.org/blog/ntfs-i30-index-attributes-evidence-of-deleted-and-overwritten-files/))
  * Since we know the malware should have been downloaded here, this is just further evidence of how it traveled through the desktop environment

**THREAT DATABASE RESEARCH**
**![Malware analysis results showing detected file signatures and threat indicators](/images/projects/stolen-szechuan-sauce/image20.png)**
Noteworthy details

* VirusTotal page for malicious IP 203.78.103.109 leads to page we found earlier for coreupdater.exe ([https://www.virustotal.com/gui/file/10f3b92002bb98467334161cf85d0b1730851f9256f83c27db125e9a0c1cfda6](https://www.virustotal.com/gui/file/10f3b92002bb98467334161cf85d0b1730851f9256f83c27db125e9a0c1cfda6)). Antivirus settings on Windows VM prevent me from getting the hash directly, meaning this is the best evidence I can obtain to demonstrate this is the appropriate page for the malware we’re studying

![Network traffic correlation showing attacker command patterns and C2C communication](/images/projects/stolen-szechuan-sauce/image21.png)

* Lists the capabilities of the malware in terms of MITRE Framework categories

![Timeline visualization of compromise events from initial access to data exfiltration](/images/projects/stolen-szechuan-sauce/image22.png)

* Results of dynamic analysis of malware on VirusTotal which provide evidence of malware relying on Metasploit Framework

![Forensic analysis artifacts showing evidence of attacker toolset and persistence mechanisms](/images/projects/stolen-szechuan-sauce/image23.png)

* MITRE ATT\&CK entry ([https://attack.mitre.org/software/](https://attack.mitre.org/software/)) listing Metasploit as a common and easily accessible tool

![Investigation summary showing key findings and indicators of compromise identified](/images/projects/stolen-szechuan-sauce/image24.png)
Confirmation of OS version on desktop using registry explorer
