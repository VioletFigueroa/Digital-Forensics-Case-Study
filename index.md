
# The Case of the Stolen Szechuan Sauce and Delosrios Forensics

## Project Overview

This project merges two comprehensive digital forensics and incident response (DFIR) investigations simulating real-world scenarios. These capstone projects for Lighthouse Labs Cybersecurity Bootcamp demonstrate end-to-end investigative methodologies, from initial evidence collection through final court-ready reporting.

### Case Scenarios

**The Incidents:**

1. FastFood Corp's secret Szechuan sauce recipe—worth millions in competitive advantage—was stolen and leaked to competitors.

2. Delosrios Corp experienced a sophisticated insider threat leading to the exfiltration of sensitive intellectual property.

As the lead digital forensics investigator, I conducted complete investigations to identify the perpetrators, reconstruct the timelines of events, and provide evidence suitable for legal proceedings.

**Investigation Goals:**

1. Identify the insider threats responsible for data theft
2. Reconstruct complete timelines of malicious activities
3. Recover deleted evidence and determine exfiltration methods
4. Document chain of custody for legal admissibility
5. Provide actionable recommendations to prevent future incidents

---

## Investigation Methodology

### Phase 1: Evidence Acquisition

**Forensic Imaging:**

- Created bit-for-bit forensic images of suspect workstations
- Documented chain of custody with MD5/SHA-256 hash verification
- Preserved volatile data (RAM) for memory forensics
- Collected network traffic captures (PCAP files)
- Secured email server logs and authentication records

**Tools Used:**

- FTK Imager - Disk imaging and evidence acquisition
- Volatility - Memory forensics framework
- Wireshark - Network traffic analysis

### Phase 2: Disk Forensics

**File System Analysis:**

- Analyzed NTFS file system metadata (MFT records)
- Recovered deleted files using forensic carving techniques
- Identified USB device connections through Windows Registry artifacts
- Examined file access timestamps (MAC times)
- Located hidden and encrypted files

**Key Findings:**

- Deleted "recipe_final.docx" recovered from unallocated space
- USB device "SANDISK_32GB" connected on day of incident
- Suspicious file copies to external storage at 2:47 AM
- Encrypted RAR archive found in temporary directory
- Browser history showing visits to competitor websites

### Phase 3: Memory Forensics

**Volatile Memory Analysis:**

Using Volatility framework, I analyzed RAM dumps to identify:

```bash
# Process analysis
vol.py -f memory.raw --profile=Win10x64 pslist
vol.py -f memory.raw --profile=Win10x64 pstree

# Network connections
vol.py -f memory.raw --profile=Win10x64 netscan

# Command history
vol.py -f memory.raw --profile=Win10x64 cmdscan
vol.py -f memory.raw --profile=Win10x64 consoles
```

**Critical Discoveries:**

- Suspicious PowerShell process executing at time of incident
- Active network connection to external file-sharing service
- Credential dumping tool (Mimikatz) evidence in memory
- Encrypted communication channel to external IP address
- Commands showing systematic file search for "sauce" and "recipe"

### Phase 4: Network Forensics

**Traffic Analysis:**

Analyzed PCAP files using Wireshark to reconstruct network activity:

- **DNS Queries** - Identified queries to file-sharing domains
- **HTTP/HTTPS Traffic** - Detected large file uploads to cloud storage
- **Email Communications** - Found suspicious emails with competitor addresses
- **FTP Transfers** - Discovered recipe file uploaded to external server
- **Exfiltration Timeline** - Confirmed data theft occurred 2:45-3:15 AM

**Evidence:**

- 2.4 MB file upload matching recipe document size
- Destination IP linked to competitor's infrastructure
- Unencrypted credentials captured in HTTP POST request
- Complete packet reassembly of stolen document

### Phase 5: Timeline Reconstruction

**Complete Attack Chains:**

```text
[2025-08-15 23:45:00] - Suspect logged in after-hours (unusual)
[2025-08-15 23:52:00] - Accessed restricted HR share containing recipes
[2025-08-16 00:15:00] - Multiple searches for "szechuan" and "sauce"
[2025-08-16 01:30:00] - Copied recipe_final.docx to Desktop
[2025-08-16 02:15:00] - Connected USB device (SANDISK_32GB)
[2025-08-16 02:45:00] - Uploaded file to external cloud storage
[2025-08-16 02:50:00] - Deleted original file and cleared recycle bin
[2025-08-16 03:00:00] - CCleaner executed to remove artifacts
[2025-08-16 03:15:00] - Logged out and disconnected USB device
```

---

## Deliverables

### Documentation and Screenshots

- **Screenshots:**
  - ![Windows Registry ProductName showing Windows Server 2012 R2 system information](../delosrios-forensics/documentation/Screenshot_20250414_130847.png)
  - ![Event Viewer logs showing security audit events and system activity during forensic analysis](../delosrios-forensics/documentation/Screenshot_20250414_142302.png)
  - ![System configuration details visible in forensic investigation of compromised server](../delosrios-forensics/documentation/Screenshot_20250414_143209.png)

- **Reports:**
  - Executive summary for management
  - Technical analysis for security team
  - Evidence summary with supporting artifacts
  - Timeline visualization and attack flow diagram

---

## Key Learnings & Insights

### Technical Skills Demonstrated

**Memory Forensics Mastery:**
Volatility framework proved essential for identifying malicious processes and network connections that would be invisible in disk-only analysis. Understanding memory structures and process artifacts is critical for modern investigations.

**Timeline Analysis:**
Reconstructing the complete attack timeline required correlating evidence from multiple sources—disk artifacts, memory dumps, network traffic, and logs. This holistic approach revealed the full scope of malicious activity.

**Anti-Forensics Awareness:**
The suspect used CCleaner and file deletion to cover tracks. This reinforced the importance of volatile memory capture and understanding where artifacts persist despite anti-forensic techniques.

---

**Related Skills:** Digital Forensics, Incident Response, Memory Analysis, Network Forensics, Evidence Collection, Legal Documentation
