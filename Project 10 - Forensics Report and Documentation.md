
#

#

#

#

#

# The Case of the Stolen Szechuan Sauce

## Juan De Los Rios

## Violet Figueroa

[Executive Summary    2](#executive-summary)

[Objective    3](#objective)

[Situation    3](#situation)

[Complication    3](#complication)

[Resolution    3](#resolution)

[Benefits and Call to Action    3](#benefits-and-call-to-action)

[Scope    4](#scope)

[Methodology    5](#methodology)

[Evidence Acquisition    5](#evidence-acquisition)

[Analysis Environment    5](#analysis-environment)

[Forensic Tools and Techniques    5](#forensic-tools-and-techniques)

[Timeline Correlation    6](#timeline-correlation)

[Documentation    6](#documentation)

[Timeline of Events    8](#timeline-of-events)

[Background and Initial Response    8](#background-and-initial-response)

[Attack Timeline    8](#attack-timeline)

[Reconnaissance Phase    8](#reconnaissance-phase)

[Data Exfiltration    9](#data-exfiltration)

[Aftermath    9](#aftermath)

[Findings    10](#findings)

[1\. What's the Operating System of the Server?    10](#1.-what's-the-operating-system-of-the-server?)

[2\. What’s the Operating System of the Desktop?    11](#2.-what’s-the-operating-system-of-the-desktop?)

[3\. What was the local time of the Server?    12](#3.-what-was-the-local-time-of-the-server?)

[4\. Was there a breach?    13](#4.-was-there-a-breach?)

[5\. What was the initial entry vector (how did they get in)?    14](#5.-what-was-the-initial-entry-vector-\(how-did-they-get-in\)?)

[6\. Was malware used? If so, what was it?    15](#6.-was-malware-used?-if-so,-what-was-it?)

[Recommendations    17](#recommendations)

[1\. Enforce Strong Password Policies    17](#1.-enforce-strong-password-policies)

[2\. Enable Multi-Factor Authentication (MFA)    17](#2.-enable-multi-factor-authentication-\(mfa\))

[3\. Enhance Logging and Monitoring    17](#3.-enhance-logging-and-monitoring)

[4\. Deploy Endpoint Detection and Response (EDR)    17](#4.-deploy-endpoint-detection-and-response-\(edr\))

[5\. Restrict Administrative Access    17](#5.-restrict-administrative-access)

[6\. Patch and Harden Systems    17](#6.-patch-and-harden-systems)

[7\. Network Segmentation    18](#7.-network-segmentation)

[8\. User Awareness and Training    18](#8.-user-awareness-and-training)

[9\. Incident Response Planning    18](#9.-incident-response-planning)

[10\. Regular Backups    18](#10.-regular-backups)

[Citations    19](#citations)

# Executive Summary {#executive-summary}

## Objective {#objective}

This report presents the findings and recommendations from a digital forensics investigation into the theft of a proprietary Szechuan sauce recipe from the organization’s main file server. The goal is to provide leadership with a clear understanding of the incident, its root causes, and actionable steps to prevent future breaches.

## Situation {#situation}

In September 2020, the organization was alerted by law enforcement that confidential intellectual property—the Szechuan sauce recipe—had appeared on the dark web. The recipe was stored on the company’s Windows Server 2012 R2 domain controller. Initial interviews with the victim revealed additional concerns about other sensitive files and highlighted a lack of detailed system knowledge among staff.

## Complication {#complication}

The investigation uncovered that an external attacker exploited weak password controls by launching a brute force attack against the server’s Administrator account. After approximately 95 failed attempts, the attacker gained administrative access, deployed malware, and established a command-and-control channel. The malware, confirmed as a Meterpreter payload, enabled the attacker to access and potentially exfiltrate sensitive files, including the Szechuan sauce recipe. The breach went undetected until the FBI’s notification, revealing significant gaps in monitoring, access controls, and incident response preparedness.

## Resolution {#resolution}

A comprehensive forensic review was conducted, including analysis of disk images, memory captures, event logs, and network traffic. The investigation confirmed the attack sequence, identified the malware and its capabilities, and mapped the attacker’s actions. Based on these findings, the report recommends immediate implementation of stronger password policies, multi-factor authentication, enhanced monitoring, endpoint protection, and user training. These measures are designed to close the security gaps exploited in this incident and align the organization’s defenses with industry best practices.

## Benefits and Call to Action {#benefits-and-call-to-action}

By adopting the recommended controls, the organization will significantly reduce its risk of future breaches, protect its intellectual property, and improve its ability to detect and respond to security incidents. Leadership is advised to prioritize these actions and allocate resources to ensure rapid implementation and ongoing security awareness.

# Scope {#scope}

This investigation focused on the compromise of the Windows Server 2012 R2 domain controller (CITADEL-DC01) within the C137.local domain. The scope included:

* Analysis of the server’s disk image and memory dump
* Review of Windows Security event logs for evidence of unauthorized access
* Network traffic analysis using PCAP files to identify malware delivery and exfiltration
* Correlation with desktop investigation findings (performed by project partner)
* Identification and documentation of the attack timeline, initial access vector, malware execution, and potential data exfiltration

The investigation period covers events from September 17, 2020, through September 19, 2020, as determined by log and memory evidence.

#

# Methodology {#methodology}

This investigation followed industry-standard digital forensic and incident response (DFIR) practices to ensure the integrity, repeatability, and reliability of findings. The following steps and tools were used:

## Evidence Acquisition {#evidence-acquisition}

* Disk and Memory Imaging:
  * The server’s disk and memory images were acquired using FTK Imager and provided as E01 and raw memory files. All images were verified with cryptographic hashes to ensure integrity.
* Log Collection:
  * Windows Security event logs (Security.evtx) were exported from the server for timeline and authentication analysis.
* Network Capture:
  * A network packet capture (PCAP) file was provided, representing network activity during the incident window.

## Analysis Environment {#analysis-environment}

* All analysis was performed in 2 identical dedicated Windows 11 virtual machines, isolated from production networks.
* Forensic images and logs were mounted as read-only to prevent modification of evidence.

## Forensic Tools and Techniques {#forensic-tools-and-techniques}

* FTK Imager (AccessData, n.d.): Used to mount and browse disk images, and to extract registry hives and log files.
* Registry Explorer (Zimmerman, n.d.): Used to examine exported registry hives for OS identification and time zone settings .
* Event Viewer (Microsoft, n.d.-a): Used to review and filter Windows Security event logs for authentication events, logon/logoff activity, and privilege escalation .
* Volatility 3  (Volatility Foundation, n.d.): Used for memory forensics, including:
  * Process enumeration (windows.psscan, windows.cmdline)
  * Network connections (windows.netscan)
  * Malware detection (windows.malfind)
  * File handle analysis (windows.filescan)
* Wireshark: Used to analyze the PCAP file, reconstruct file downloads, and correlate network activity with logon events (Wireshark Foundation, n.d.).
* VirusTotal: Used to scan suspicious executables (e.g., coreupdater.exe) identified in the PCAP and memory analysis (VirusTotal, n.d.).

## Timeline Correlation {#timeline-correlation}

All timestamps were normalized to the server’s local time zone (PDT/UTC-7) as determined from registry and event log analysis. Events from logs, memory, and network captures were correlated to reconstruct the attack sequence.

## Documentation {#documentation}

Throughout this investigation, we prioritized transparency, repeatability, and defensibility in all forensic processes. We began by acquiring forensic images of the server’s disk and memory using FTK Imager, ensuring the integrity of each image with cryptographic hash verification (AccessData, n.d.). Windows Security event logs (Security.evtx) and network packet captures (PCAP) were also collected to provide a comprehensive view of system and network activity during the incident window.
Analysis was conducted in isolated Windows 11 virtual machines, with all evidence mounted as read-only to prevent accidental modification. We used a suite of industry-standard tools, including Registry Explorer for registry hive analysis (Zimmerman, n.d.), Event Viewer for log review (Microsoft, n.d.-a), Volatility 3 for memory forensics (Volatility Foundation, n.d.), Wireshark for network traffic analysis (Wireshark Foundation, n.d.), and VirusTotal for malware identification (VirusTotal, n.d.). Each tool was selected for its reliability and acceptance in the digital forensics community.
For each investigative question, we documented not only the answer but also the path to discovery. For example, to determine the operating system of the desktop, Juan extracted the SOFTWARE registry hive from the disk image and used Registry Explorer to locate the ProductName value under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion, confirming the OS as Windows 10 Enterprise Evaluation (see Figure 2; Zimmerman, n.d.). To establish the server’s local time zone, Violet examined both the SYSTEM registry hive and System event logs, cross-referencing the TimeZoneKeyName value and time zone change events (see Figure 3; Microsoft, n.d.-a).
The breach was identified by correlating a sequence of failed and successful logon events in the Security event logs (Event IDs 4625, 4776, and 4672), which matched the MITRE ATT\&CK description of brute force attacks (MITRE, n.d.). Memory analysis with Volatility 3 revealed the presence of a suspicious process, coreupdater.exe, which was further investigated through network analysis in Wireshark. Juan identified the external IP address that delivered the malware and the command-and-control server it contacted, while VirusTotal confirmed the file’s malicious nature and capabilities (VirusTotal, n.d.; Wireshark Foundation, n.d.).
All findings were supported with annotated screenshots, direct log excerpts, and references to tool outputs. We maintained detailed notes on each step, ensuring that the investigation could be independently verified and reproduced. This comprehensive documentation approach not only supports the conclusions presented in the report but also aligns with industry best practices for digital forensics and incident response (DFIR Madness, n.d.; Volatility Foundation, n.d.; MITRE, n.d.).

#

# Timeline of Events {#timeline-of-events}

## Background and Initial Response {#background-and-initial-response}

In September 2020, a renowned mad scientist discovered that his recently-developed Szechuan sauce recipe had been found on the dark web by the FBI (DFIR Madness, n.d.). The scientist, known for his eccentric behavior (evidenced by his frequent belching during the interview), immediately demanded an investigation. During the initial interview, he revealed that the stolen recipe was stored on "the *bellllcchhhh* \[sic\] File Server on the Domain Controller." When questioned about system details, he could only state that "Whatever that idiot Jerry put on there a few years back" was running on the server.
The affected network infrastructure used IP addresses in the 10.42.x.x range, and the incident occurred in Colorado (UTC-6 timezone). The scientist also expressed concern about other potentially compromised data, including files belonging to someone named "Morty" and a particularly sensitive secret about "Beth" that he emphatically warned should remain confidential.

## Attack Timeline {#attack-timeline}

### Reconnaissance Phase {#reconnaissance-phase}

The attacker began by scanning the network, likely identifying the Windows Server 2012 R2 domain controller as a primary target. The network traffic analysis showed methodical enumeration of services prior to the actual attack attempt.
Initial Access Attempt (September 18, 2020, 8:21:25 PM)
The attack began with a brute force campaign against the Administrator account from a system named "kali" (a specialized Linux distribution used for penetration testing). Event logs captured approximately 95 rapid authentication attempts using NTLM authentication (Logon Type 3), with each attempt failing due to incorrect passwords (Failure Reason: "%%2313" with SubStatus code 0xc000006a indicating "bad password").
Successful Compromise (September 18, 2020, 8:56:03 PM)
After multiple attempts, the attacker successfully validated credentials for the Administrator account as documented in Event ID 4776:

* Logon Account: Administrator
* Workstation Name: kali
* Error Code: 0x0 (Success)

This was immediately followed by special logon events (Event ID 4672), granting the attacker elevated privileges on the domain controller.
Malware Deployment (September 18, 2020, \~8:56 PM)
Shortly after gaining administrative access, the attacker deployed malware to the system. Network capture data showed the download of a suspicious executable named "coreupdater.exe" from a malicious URL. Volatility 3 (AccessData, n.d.) memory analysis later confirmed the presence of this suspicious process (PID 3644\) running on the server.
The malware was downloaded to the desktop at \`c:\\windows\\system32\\coreupdater.exe\`.

### Data Exfiltration {#data-exfiltration}

Following the compromise, the attacker specifically targeted and located the Szechuan sauce recipe. PCAP analysis revealed outbound traffic consistent with data exfiltration, including the recipe and potentially the secret file related to "Beth" that the scientist had mentioned.

### Aftermath {#aftermath}

The breach was only discovered after the FBI notified the scientist that his Szechuan sauce recipe had been found on the dark web. Analysis of the Domain Controller (DC01) and a desktop system revealed the extent of the compromise.
The incident highlighted several security weaknesses in the environment, including insufficient access controls, lack of monitoring for brute force attempts, and vulnerable server configurations that failed to detect or prevent unauthorized access and subsequent data theft.
The scientist, clearly agitated during the investigation, emphasized the sensitivity of the stolen data with the memorable threat: "if you find it, and YOU TELL ANYBODY I WILL KILL YOU\!"
This incident demonstrates how targeted attacks can successfully compromise systems to steal intellectual property like the prized Szechuan sauce recipe, especially when proper security controls are not in place.

#

# Findings {#findings}

We've organized findings according to the core questions, documenting how each answer was discovered with supporting evidence.

## 1\. What's the Operating System of the Server? {#1.-what's-the-operating-system-of-the-server?}

Violet determined that the server was running Windows Server 2012 R2 Standard Evaluation by extracting the SOFTWARE registry hive from the server disk image and analyzing it with Registry Explorer. Navigating to the HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion key, they found the ProductName value clearly listed as "Windows Server 2012 R2 Standard Evaluation," (see Figure 1). This was further supported by the presence of typical Windows system processes in memory analysis.

![Windows Registry value showing ProductName as Windows Server 2012 R2 Standard Evaluation](/images/projects/stolen-szechuan-sauce/image1.png)
Figure 1: Registry Explorer showing the ProductName value as Windows Server 2012 R2 Standard Evaluation.

## 2\. What’s the Operating System of the Desktop? {#2.-what’s-the-operating-system-of-the-desktop?}

Juan identified the desktop operating system as Windows 10 Enterprise Evaluation by examining the SOFTWARE registry hive from the desktop disk image using Registry Explorer. He navigated to the HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion key, where the ProductName value was "Windows 10 Enterprise Evaluation," and confirmed this finding with additional fields such as CurrentBuild and EditionID, providing clear and reliable evidence of the desktop’s OS version (see Figure 2).

![System event log showing significant security-related activity during forensic analysis](/images/projects/stolen-szechuan-sauce/image2.png)
Figure 2: Registry Explorer showing CompositionEditionID as EnterpriseEval.

## 3\. What was the local time of the Server? {#3.-what-was-the-local-time-of-the-server?}

Violet determined the server’s local time zone by examining both the SYSTEM registry hive and the System event logs from the server disk image. Using Registry Explorer, they navigated to the ControlSet001\\Control\\TimeZoneInformation key, where the TimeZoneKeyName value was set to "Pacific Standard Time," confirming the server was configured for the PST (UTC-8) time zone. This finding was corroborated by reviewing the System event logs, which included entries documenting a time zone change and system time adjustments, further validating the server’s time configuration. Establishing the correct local time zone was essential for accurately correlating event log timestamps, memory artifacts, and network activity throughout the investigation (see Figure 3; Zimmerman, n.d.; Microsoft, n.d.-a).

![Additional forensic evidence showing system configuration changes during attack](/images/projects/stolen-szechuan-sauce/image3.png)
Figure 3: TimeZoneKeyName in System.evtx logs showing as Pacific Standard Time.

## 4\. Was there a breach? {#4.-was-there-a-breach?}

Violet’s memory forensics using Volatility 3 (AccessData, n.d.) revealed a suspicious process, "coreupdater.exe" (appearing as "coreupdater.ex" in memory, see Figure 4.1, 4.2), running with PID 3644 and no command line or file path, suggesting anti-forensic or fileless malware techniques; Juan’s network analysis further confirmed that this executable was downloaded from a malicious URL and identified as malware by VirusTotal, establishing its role in the attack.
![Security log entries documenting attack progression and attacker actions](/images/projects/stolen-szechuan-sauce/image4.png)
Figure 4.1: "coreupdater.ex" in server process list from Volatility 3 (AccessData, n.d.). **![Network forensics results showing traffic patterns from compromised system](/images/projects/stolen-szechuan-sauce/image5.png)**
**![Log analysis showing system events relevant to incident timeline reconstruction](/images/projects/stolen-szechuan-sauce/image6.png)**
Figure 4.2: Unusual process in desktop listed as coreupdate.exe with PID 8324\.

##

## 5\. What was the initial entry vector (how did they get in)? {#5.-what-was-the-initial-entry-vector-(how-did-they-get-in)?}

Violet confirmed that a breach occurred on the server by analyzing the Windows Security event logs, which revealed a clear sequence of unauthorized access events. The payload was delivered from the external IP address 194.61.24.102 via an HTTP download using Internet Explorer after the attacker gained access through RDP (see Figure 5.1). The logs showed approximately 95 failed logon attempts targeting the Administrator account from a system named "kali" (Event ID 4625, see Figure 5.2), followed by a successful credential validation (Event ID 4776, see Figure 5.3) and the assignment of special privileges (Event ID 4672, see Figure 5.3) to the same account, all within a short time frame. This pattern is consistent with a brute force attack as described in MITRE ATT\&CK technique T1110 (MITRE, n.d.), and the successful logon marks the point at which the attacker gained unauthorized administrative access to the server. The evidence is further supported by the subsequent execution of malware and suspicious activity observed in memory and network analysis, confirming that the breach was both successful and impactful.

![Detailed attack chain visualization showing attacker progression through network](/images/projects/stolen-szechuan-sauce/image7.png)
Figure 5.1: Confirmation that malicious IP address communicated with desktop machine as well as the server. ![Failed login attempts displayed in Event Viewer showing brute force activity](/images/projects/stolen-szechuan-sauce/image8.png)
Figure 5.2 Multiple Event ID 4625 (ManageEngine, n.d.) entries showing failed attempts. ![Multiple security events showing coordinated failed authentication attempts on systems](/images/projects/stolen-szechuan-sauce/image9.png)
Figure 5.3 Successful authentication (Event ID 4672, ManageEngine. (n.d.)). Followed by the assignment of special privileges (Event ID 4672, ManageEngine. (n.d.)).

## 6\. Was malware used? If so, what was it? {#6.-was-malware-used?-if-so,-what-was-it?}

Violet and Juan’s combined analysis confirmed that malware was used in the attack, specifically a malicious process named coreupdater.exe (also appearing as coreupdater.ex in memory analysis) delivered from IP 192.61.24.102 (see Figure 6.1), which was identified running on the server with PID 3644 (see Figure 4.1). Once executed, the malware established a command-and-control connection to 203.78.103.109, as confirmed by the network analysis (see Figure 6.2). The executable was initially downloaded to the Administrator’s Downloads folder and then moved to C:\\Windows\\System32\\coreupdater.exe. The first appearance of the malware on disk was shortly after the successful brute force attack, specifically on September 18, 2020, at approximately 8:56 PM PST, and it was moved to the System32 directory to facilitate persistence. The malware’s capabilities were extensive, as it was most likely a Meterpreter payload from the Metasploit Framework (MITRE. (n.d.)), enabling process migration, credential theft, keylogging, screen scraping, and a wide range of post-exploitation modules. This malware is easily obtained, as Metasploit is a free and widely available penetration testing toolkit. Persistence was achieved by installing the malware as a Windows AutoStart service with Local System privileges and by creating registry entries, ensuring it would survive reboots and maintain access. The malware was installed with persistence on both the server and the desktop, with installation and movement times corresponding to the attacker’s lateral movement and privilege escalation activities (see Figure 6.3). The malicious nature of coreupdater.exe was confirmed by Virus Total (VirusTotal. (n.d.)), see Figure 6.4).
![Security event logs showing multiple failed authentication attempts and lateral movement indicators](/images/projects/stolen-szechuan-sauce/image10.png)
Figure 6.1: Wireshark PCAP (Wireshark Foundation. (n.d.)) showing malicious IP 192.61.24.102 delivering the payload, coreupdater.exe.
**![Wireshark packet capture showing network traffic analysis for incident investigation](/images/projects/stolen-szechuan-sauce/image11.png)**
Figure 6.2: A foreign address, 203.78.103.109 port 443, establishes a connection with the desktop twice.
![Process execution logs showing suspicious executable files and their command-line parameters](/images/projects/stolen-szechuan-sauce/image12.png)Figure 6.3 : Absence of coreupdater.exe in Volatility 3 (AccessData, n.d.) filescan results.
![Event logs showing remote desktop connection attempts to the compromised system](/images/projects/stolen-szechuan-sauce/image13.png)
Figure 6.4: coreupdater.exe flagged as Malicious by Virus Total (VirusTotal. (n.d.)).

# Recommendations {#recommendations}

Based on the forensic analysis of the Szechuan Sauce case (DFIR Madness, n.d.), the following recommendations are made to address the weaknesses exploited by the attacker and to improve the overall security posture of the organization:

## 1\. Enforce Strong Password Policies {#1.-enforce-strong-password-policies}

* Require complex, unique passwords for all administrative and user accounts.
* Implement account lockout policies to prevent brute force attacks, such as limiting failed login attempts and introducing time delays after repeated failures.

## 2\. Enable Multi-Factor Authentication (MFA) {#2.-enable-multi-factor-authentication-(mfa)}

* Deploy MFA for all remote and privileged access, especially for domain controllers and sensitive servers.

## 3\. Enhance Logging and Monitoring {#3.-enhance-logging-and-monitoring}

* Ensure that all critical systems have security logging enabled and that logs are retained for an adequate period.
* Regularly review logs for signs of brute force attempts, unusual logon times, and privilege escalation.
* Implement centralized log management and alerting for suspicious activity.

## 4\. Deploy Endpoint Detection and Response (EDR) {#4.-deploy-endpoint-detection-and-response-(edr)}

* Use EDR solutions to detect and respond to malware, fileless attacks, and suspicious process activity.
* Regularly update endpoint protection signatures and monitor for alerts related to known attack tools.

## 5\. Restrict Administrative Access {#5.-restrict-administrative-access}

* Limit the use of domain administrator accounts and use just-in-time (JIT) access where possible.
* Segregate administrative duties and use separate accounts for administrative and day-to-day activities.

## 6\. Patch and Harden Systems {#6.-patch-and-harden-systems}

* Regularly apply security patches to operating systems and applications.
* Remove or disable unnecessary services and software, especially those exposed to the network.

## 7\. Network Segmentation {#7.-network-segmentation}

* Segment critical servers from user workstations and limit lateral movement opportunities.
* Restrict inbound and outbound network traffic to only what is necessary for business operations.

## 8\. User Awareness and Training {#8.-user-awareness-and-training}

* Educate users and administrators about phishing, password security, and social engineering risks.
* Conduct regular security awareness training and simulated attack exercises.

## 9\. Incident Response Planning {#9.-incident-response-planning}

* Develop and regularly test an incident response plan to ensure rapid detection, containment, and recovery from future attacks.
* Maintain up-to-date contact lists and escalation procedures.

## 10\. Regular Backups {#10.-regular-backups}

* Ensure regular, secure backups of critical data and system configurations.
* Test backup restoration procedures to ensure data can be recovered in the event of ransomware or destructive attacks.

Implementing these recommendations will significantly reduce the risk of similar attacks and improve the organization’s ability to detect, respond to, and recover from security incidents.

#

# Citations {#citations}

1. DFIR Madness. (n.d.). The Stolen Szechuan Sauce \- Case 001\. [https://dfirmadness.com/the-stolen-szechuan-sauce/](https://dfirmadness.com/the-stolen-szechuan-sauce/)
2. Volatility Foundation. (n.d.). Volatility 3 Documentation. [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)
3. ManageEngine. (n.d.). Windows Security Log Event ID 4625: An account failed to log on. [https://www.manageengine.com/products/active-directory-audit/kb/windows-security-log-event-id-4625.html](https://www.manageengine.com/products/active-directory-audit/kb/windows-security-log-event-id-4625.html)
4. ManageEngine. (n.d.). Windows Security Log Event ID 4776: The computer attempted to validate the credentials for an account. [https://www.manageengine.com/products/active-directory-audit/kb/windows-security-log-event-id-4776.html](https://www.manageengine.com/products/active-directory-audit/kb/windows-security-log-event-id-4776.html)
5. ManageEngine. (n.d.). Windows Security Log Event ID 4672: Special privileges assigned to new logon. [https://www.manageengine.com/products/active-directory-audit/kb/logon-logoff-events/event-id-4672.html](https://www.manageengine.com/products/active-directory-audit/kb/logon-logoff-events/event-id-4672.html)
6. Wireshark Foundation. (n.d.). Wireshark User Documentation. [https://www.wireshark.org/docs/](https://www.wireshark.org/docs/)
7. AccessData. (n.d.). FTK Imager User Guide. [https://accessdata.com/product-download/ftk-imager-version-4-7-1](https://accessdata.com/product-download/ftk-imager-version-4-7-1)
8. Eric Zimmerman. (n.d.). Registry Explorer Documentation. [https://ericzimmerman.github.io/\#\!index.md](https://ericzimmerman.github.io/#!index.md)
9. Microsoft. (n.d.). Event Viewer. [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-viewer-security-logs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-viewer-security-logs)
10. VirusTotal. (n.d.). VirusTotal Documentation. [https://docs.virustotal.com/docs/how-it-works](https://docs.virustotal.com/docs/how-it-works)
11. MITRE. (n.d.). Brute Force, Technique T1110. MITRE ATT\&CK®. [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)
12. MITRE. (n.d.). Metasploit \[S0086\]. MITRE ATT\&CK®. [https://attack.mitre.org/software/S0086/](https://attack.mitre.org/software/S0086/)
