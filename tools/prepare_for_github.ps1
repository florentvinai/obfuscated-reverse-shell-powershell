# Script pour preparer les fichiers avant publication GitHub
# Remplace les IPs hardcodees par des placeholders

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Preparation pour GitHub" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Chemin vers les scripts
$scriptsPath = Join-Path $PSScriptRoot "..\scripts"
$files = @(
    "reverse_shell_process_hollowing_syscallsv2.ps1",
    "reverse_shell_dll_memory.ps1",
    "reverse_shell.ps1",
    "reverse_shell_process_hollowing_syscalls.ps1",
    "reverse_shell_dll_memory_edr_bypass.ps1",
    "reverse_shell_process_injection_advanced.ps1"
)

# IP actuelle encodee en Base64
$currentIPBase64 = 'MTkyLjE2OC4xOTkuMTUw'
# IP placeholder (192.168.1.100) encodee en Base64
$placeholderIPBase64 = 'MTkyLjE2OC4xLjEwMA=='

$count = 0
foreach ($file in $files) {
    $filePath = Join-Path $scriptsPath $file
    if (Test-Path $filePath) {
        $content = Get-Content $filePath -Raw
        if ($content -match $currentIPBase64) {
            $content = $content -replace $currentIPBase64, $placeholderIPBase64
            $content | Set-Content $filePath -NoNewline
            Write-Host "[+] Modifie: scripts\$file" -ForegroundColor Green
            $count++
        } else {
            Write-Host "[*] Deja OK: scripts\$file" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[!] Non trouve: scripts\$file" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[+] $count fichier(s) modifie(s)" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Note: L'IP a ete remplacee par 192.168.1.100 (placeholder)" -ForegroundColor Yellow
Write-Host "[*] Les utilisateurs devront modifier l'IP selon leurs besoins" -ForegroundColor Yellow
Write-Host ""

