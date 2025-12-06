# The Case of the Stolen Szechuan Sauce

![GitHub last commit](https://img.shields.io/github/last-commit/VioletFigueroa/Digital-Forensics-Case-Study?style=flat-square)
![GitHub repo size](https://img.shields.io/github/repo-size/VioletFigueroa/Digital-Forensics-Case-Study?style=flat-square)
![License](https://img.shields.io/badge/license-Educational-blue?style=flat-square)
![Release](https://img.shields.io/github/v/release/VioletFigueroa/Digital-Forensics-Case-Study?style=flat-square)

**Quick Links:** [Documentation](README.md) | [Security Policy](SECURITY.md) | [Contributing](CONTRIBUTING.md) | [Release](https://github.com/VioletFigueroa/Digital-Forensics-Case-Study/releases/tag/v1.0.0)

---

## Overview
Comprehensive digital forensics and incident response investigation into the theft of a proprietary Szechuan sauce recipe and intellectual property exfiltration. This merged project combines two distinct forensics case studies demonstrating real-world investigative methodologies suitable for legal proceedings and corporate incident response.

## Objectives
- Identify insider threats responsible for data theft
- Reconstruct complete timelines of malicious activities  
- Recover deleted evidence and determine exfiltration methods
- Document chain of custody for legal admissibility
- Provide actionable recommendations to prevent future incidents

## Methodology
**Evidence Acquisition:**
- Created bit-for-bit forensic images of suspect workstations with MD5/SHA-256 hash verification
- Preserved volatile data (RAM) for memory forensics
- Collected network traffic captures (PCAP files)
- Maintained strict chain of custody documentation

**Analysis Environment:**
- Deployed dedicated forensic analysis lab with forensically sound equipment
- All evidence mounted as read-only to prevent modification
- Comprehensive logging of all analysis activities

**Forensic Tools and Techniques:**
- Registry Explorer for registry hive analysis
- Event Viewer for log review and timeline correlation
- Volatility 3 for memory forensics
- Wireshark for network traffic analysis
- VirusTotal for malware identification

## Key Findings
- Identified perpetrators through forensic artifacts and timeline correlation
- Reconstructed complete incident timelines with supporting evidence
- Determined exfiltration methods and data paths
- Documented malicious activities suitable for legal proceedings
- Identified security gaps enabling the insider threats

## Technologies Used
- Volatility 3 - Memory forensics and analysis
- Wireshark - Network traffic analysis
- Registry Explorer - Windows registry analysis
- Event Viewer - System event log analysis
- VirusTotal - Malware identification
- Bash scripting - Forensic automation and log processing
- PCAP file analysis - Network packet capture examination
- Chain of custody documentation - Legal evidence preservation

## Files Included
- [Project 10 - Forensics Report and Documentation.md](Project%2010%20-%20Forensics%20Report%20and%20Documentation.md) - Full investigation report with findings
- [Project 10 - Forensics Report and Documentation.docx](Project%2010%20-%20Forensics%20Report%20and%20Documentation.docx) - Formal documentation in Word format
- [images/](images/) - Forensic screenshots and visual evidence
- [notes/](notes/) - Detailed investigative notes and analysis
