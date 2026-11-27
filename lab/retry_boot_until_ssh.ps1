# Reinicia una VM del laboratorio hasta que su SSH (reenviado por NAT) responda de forma
# estable. Util para comprobar la estabilidad de arranque bajo el backend NEM.
#
# Uso: .\lab\retry_boot_until_ssh.ps1 -VmName victima-01 -NatSshPort 22101
param(
    [Parameter(Mandatory=$true)][string]$VmName,
    [Parameter(Mandatory=$true)][int]$NatSshPort,
    [int]$MaxAttempts = 10,
    [int]$MaxMinutesPerAttempt = 4
)

$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

function Wait-Ssh($port, $maxMinutes) {
    $deadline = (Get-Date).AddMinutes($maxMinutes)
    $consecutive = 0
    while ((Get-Date) -lt $deadline) {
        $out = & ssh -p $port -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no lab@127.0.0.1 exit 2>&1
        $text = $out -join " "
        if ($text -match "Permission denied" -or $text -match "Host key verification") {
            $consecutive++
            if ($consecutive -ge 3) { return $true }
        } else {
            $consecutive = 0
        }
        Start-Sleep -Seconds 8
    }
    return $false
}

for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    Write-Output "=== $VmName : intento $attempt de $MaxAttempts : poweroff + startvm ==="
    & $vbox controlvm $VmName poweroff
    Start-Sleep -Seconds 4
    & $vbox startvm $VmName --type headless
    if (Wait-Ssh -port $NatSshPort -maxMinutes $MaxMinutesPerAttempt) {
        Write-Output "=== $VmName : SSH ESTABLE (3x) tras el intento $attempt ==="
        exit 0
    }
    Write-Output "=== $VmName : intento $attempt fallo ==="
}
Write-Output "=== $VmName : FALLO tras $MaxAttempts intentos ==="
exit 1
