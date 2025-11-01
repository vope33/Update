$start = Get-Date

try {
    $response = Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing -TimeoutSec 5
    Write-Host "Connexion Internet détectée." -ForegroundColor Green
}
catch {
    Write-Warning "Pas de connexion Internet détectée. Arrêt du script."
    exit
}


# DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase


# Vérification des droits administrateur
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Warning "Veuillez exécuter ce script en tant qu'administrateur."
    Exit 1
}


# --- Réinitialisation de Windows Update ---
Write-Host "===== Réinitialisation des composants Windows Update =====" -ForegroundColor Cyan

Write-Host "Renommage du dossier SoftwareDistribution..." -ForegroundColor DarkGray
$sdPath = "C:\Windows\SoftwareDistribution"
if (Test-Path $sdPath) {
    $backupPath = "C:\Windows\SoftwareDistribution.old_{0:yyyyMMdd_HHmm}" -f (Get-Date)
    Rename-Item -Path $sdPath -NewName $backupPath -ErrorAction SilentlyContinue
}

Write-Host "Renommage du dossier catroot2..." -ForegroundColor DarkGray
$catrootPath = "C:\Windows\System32\catroot2"
if (Test-Path $catrootPath) {
    $backupCatroot = "C:\Windows\System32\catroot2.old_{0:yyyyMMdd_HHmm}" -f (Get-Date)
    Rename-Item -Path $catrootPath -NewName $backupCatroot -ErrorAction SilentlyContinue
}


Start-Service wuauserv,bits,cryptsvc,msiserver


# --- Activation de Microsoft Update ---
Write-Host "===== Activation de Microsoft Update (si désactivé) =====" -ForegroundColor Cyan
$MUPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d"
if (-not (Test-Path $MUPath)) {
    Write-Host "Activation de Microsoft Update..."
    New-Item -Path $MUPath -Force | Out-Null
    New-ItemProperty -Path $MUPath -Name "RegisteredWithAU" -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Host "Microsoft Update activé."
} else {
    Write-Host "Microsoft Update déjà activé."
}


# --- Mise à jour Windows + Microsoft Update ---
Write-Host "===== Mise à jour Windows + Microsoft Update =====" -ForegroundColor Cyan
Try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
} Catch {
    Write-Warning "Le module PSWindowsUpdate n'est pas installé. Installation..."

    # Vérifie que PSGallery est bien configuré et approuvé
    if (-not (Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue)) {
        Register-PSRepository -Default
    }
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    # Installe le module depuis le dépôt officiel
    Install-Module -Name PSWindowsUpdate -Repository PSGallery -Scope AllUsers -Force -Confirm:$false
    
    Import-Module PSWindowsUpdate
}

Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -Verbose







Write-Host "===== Mise à jour Microsoft Office =====" -ForegroundColor Cyan
# Microsoft Office via ClickToRun
$officeC2R = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
If (Test-Path $officeC2R) {
Start-Process $officeC2R -ArgumentList "/update user" -Wait
Write-Host "Microsoft Office a été mis à jour."
} Else {
Write-Warning "Microsoft Office n'a pas été trouvé (ClickToRun)."
}




Write-Host "===== Synchronisation des sources Winget =====" -ForegroundColor Cyan
winget source update
winget source list
if (-not (winget source list | Select-String "msstore")) {
    winget source add --name msstore --arg https://storeedgefd.dsx.mp.microsoft.com/v9.0
}

Write-Host "===== Mise à jour de toutes les applications (Winget + Store si liées) =====" -ForegroundColor Cyan
winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements




Write-Host "===== Mise à jour des applications Winget =====" -ForegroundColor Cyan
Try {
    winget upgrade --all --accept-source-agreements --accept-package-agreements
} Catch {
    Write-Warning "Winget n'est pas installé ou non disponible."
}




Write-Host "===== Mise à jour des applications du Microsoft Store =====" -ForegroundColor Cyan
if (Get-Process -Name "explorer" -ErrorAction SilentlyContinue) {
    Write-Host "Session utilisateur détectée. Lancement du Microsoft Store..." -ForegroundColor Cyan
    Start-Process "ms-windows-store://downloadsandupdates"
} else {
    Write-Warning "Aucune session utilisateur active (explorer.exe introuvable)."
    Write-Warning "La mise à jour du Microsoft Store ne peut pas être lancée dans une session non interactive."
}




Get-ChildItem "C:\Windows" -Directory -Filter "SoftwareDistribution.old_*" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue



Write-Host "Vérification si un redémarrage est requis..." -ForegroundColor Cyan

if ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) -or
    (Test-Path "C:\Windows\WinSxS\pending.xml")) {
    Write-Host "Un redémarrage est nécessaire. Il sera lancé dans 30 secondes..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
    Restart-Computer -Force
} else {
    Write-Host "Aucun redémarrage nécessaire." -ForegroundColor Green
}

DISM /Online /Cleanup-Image /StartComponentCleanup


$end = Get-Date
Write-Host "Durée totale : $((New-TimeSpan -Start $start -End $end).ToString())"


Pause
