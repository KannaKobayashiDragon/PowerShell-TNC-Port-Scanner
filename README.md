# 📡 PowerShell-TNC-Port-Scanner

**Native PowerShell TCP Port Scanner with CIDR Support**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

---

## 📖 Description

A production-ready PowerShell script that performs TCP port scanning using the native `Test-NetConnection` cmdlet. Designed for network administrators and security professionals who need to scan single hosts, multiple IP addresses, or entire network ranges using CIDR notation.

**Key Features:**
- ✅ Scan hostnames, IPs, or CIDR ranges (e.g., `192.168.1.0/24`)
- ✅ Flexible port specification: single (`80`), ranges (`1-1024`), or lists (`22,80,443`)
- ✅ Comprehensive input validation and error handling
- ✅ Interactive or command-line modes
- ✅ Color-coded output and detailed scan summaries
- ✅ Export results to CSV/JSON via PowerShell pipeline

---

## 🤖 AI Coding Stack

**AI Language Models & Their Roles:**
- ✅ Gemini 3 Pro (Education License) : Used for advanced prompt engineering and idea exploration.
- ✅ Cursor (Free Edition) : Assists with code refinement, debugging, and restructuring.
- ✅ Claude Sonnet 4.5 (Free Edition) : Primary coding assistant for core development tasks.
- ✅ ChatGPT (GPT-5.1, Free Edition) : Grammar rewriting, and technical prompt engineering.

---

## 🚀 Quick Start 1 (Command Prompt)

```powershell
# Script Bypass Policy PowerShell (cmd.exe)
PowerShell -ep bypass 

# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/KannaKobayashiDragon/PowerShell-TNC-Port-Scanner/main/PowerShell-TNC-Port-Scanner-Advanced.ps1" -OutFile "PowerShell-TNC-Port-Scanner-Advanced.ps1"

# Import the function (Do not use Import-Module)
$scriptContent = Get-Content "PowerShell-TNC-Port-Scanner.ps1" -Raw -Encoding UTF8
Invoke-Expression $scriptContent

# Verify it loaded correctly
Get-Command Invoke-NetworkPortScan

# Scan a single host
Invoke-NetworkPortScan -TargetHost "192.168.1.100" -PortSpecification "80,443"

# Scan entire subnet
Invoke-NetworkPortScan -TargetHost "10.0.1.0/24" -PortSpecification "22,3389"

# Interactive mode
Invoke-NetworkPortScan
```

---

## 🚀 Quick Start 2 (Windows PowerShell ISE)

```powershell
# Windows PowerShell ISE
Launch Windows PowerShell ISE

# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/KannaKobayashiDragon/PowerShell-TNC-Port-Scanner/main/PowerShell-TNC-Port-Scanner-Advanced.ps1" -OutFile "PowerShell-TNC-Port-Scanner-Advanced.ps1"

# Import the function (Do not use Import-Module)
Paste The Script into Script section
Run the Script

# Verify it loaded correctly
Get-Command Invoke-NetworkPortScan

# Scan a single host - PowerShell Terminal
Invoke-NetworkPortScan -TargetHost "192.168.1.100" -PortSpecification "80,443"

# Scan entire subnet - PowerShell Terminal
Invoke-NetworkPortScan -TargetHost "10.0.1.0/24" -PortSpecification "22,3389"

# Interactive mode - PowerShell Terminal
Invoke-NetworkPortScan
```


## 📋 Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later (pre-installed on Windows)
- No external dependencies or modules required

---

## 💡 Usage Examples

```powershell
# Scan common ports
Invoke-NetworkPortScan -TargetHost "DC01" -PortSpecification "8080"

# Scan port range with verbose output
 Invoke-NetworkPortScan -TargetHost "192.168.102.207" -PortSpecification "8080,80,443" -Verbose

```

---

## ⚠️ LEGAL WARNING & DISCLAIMER

### 🚨 READ THIS BEFORE USING

**This tool is for AUTHORIZED use ONLY. Unauthorized port scanning is illegal in many jurisdictions.**

### ✅ Authorized Use
You **MAY** use this tool **ONLY** when:
- You own the network being scanned
- You have explicit written permission from the network owner
- You are conducting authorized security assessments
- You are working in an isolated lab environment for education

### ❌ Prohibited Use
You **MUST NOT** use this tool to:
- Scan networks without authorization
- Attempt unauthorized access to computer systems
- Conduct malicious activity of any kind
- Violate computer fraud and abuse laws
- Breach your ISP's terms of service

### ⚖️ Legal Consequences

**Unauthorized scanning can result in:**
- Criminal prosecution under computer fraud laws (e.g., CFAA in the USA)
- Civil lawsuits and financial damages
- Termination of internet service
- Job loss and professional consequences
- Imprisonment in severe cases

### 🛡️ Your Responsibility

By using this tool, you acknowledge that:
1. You understand the legal risks of unauthorized network scanning
2. You will only use this tool on networks you are authorized to scan
3. You will comply with all applicable laws and regulations
4. You accept full responsibility for your actions
5. The authors are not liable for any misuse of this tool

**When in doubt, don't scan. Always get written permission first.**

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions welcome! Please submit issues or pull requests on GitHub.

---

<div align="center">

**Use Responsibly. Stay Legal. Get Permission.**

Made for authorized network administration and security testing only.

</div>
