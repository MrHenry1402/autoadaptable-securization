# Crea e instala desatendidamente una VM Debian del laboratorio (labnet).
#
# Uso:
#   .\lab\provision_vm.ps1 -VmName victima-01 -NatSshPort 22101 -Password <contrasena>
#
# La contrasena se pasa como argumento y nunca se guarda en el repositorio
# (vease lab-credentials.local.txt, ignorado por git). La IP estatica de labnet se
# fija despues con lab/set_static_ip.py.
#
# Configuracion de CPU: con Hyper-V activo en la torre, VirtualBox usa el backend NEM y
# los invitados con varias vCPU o con IO-APIC se cuelgan al arrancar (ver docs/lab-design.md).
param(
    [Parameter(Mandatory=$true)][string]$VmName,
    [Parameter(Mandatory=$true)][int]$NatSshPort,
    [Parameter(Mandatory=$true)][string]$Password,
    [string]$Iso = "C:\Users\euqui\VBoxISOs\debian-13.7.0-amd64-netinst.iso",
    [string]$HostOnlyIf = "VirtualBox Host-Only Ethernet Adapter #2",
    [int]$MaxMinutesPerStage = 25
)

$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$diskPath = "C:\Users\euqui\VirtualBox VMs\$VmName\$VmName.vdi"
# Plantilla de preseed corregida: la de VirtualBox no fija tasksel/first y a veces
# instala un escritorio GNOME completo en lugar de un sistema minimo con SSH.
$preseedTemplate = Join-Path $PSScriptRoot "debian_preseed_minimal.cfg"

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
        Start-Sleep -Seconds 10
    }
    return $false
}

function Wait-SshWithRetries($maxAttempts, $stage) {
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        if ($attempt -gt 1) {
            Write-Output "=== $VmName : $stage intento $($attempt-1) fallo, reiniciando ==="
            & $vbox controlvm $VmName poweroff
            Start-Sleep -Seconds 5
            & $vbox startvm $VmName --type headless
        }
        if (Wait-Ssh -port $NatSshPort -maxMinutes $MaxMinutesPerStage) { return $true }
    }
    return $false
}

# Si ya existe, borrarla para partir de cero.
$existing = & $vbox list vms
if ($existing -match [regex]::Escape("`"$VmName`"")) {
    Write-Output "=== $VmName : borrando instancia previa ==="
    & $vbox controlvm $VmName poweroff
    Start-Sleep -Seconds 5
    & $vbox unregistervm $VmName --delete
}

Write-Output "=== $VmName : createvm + almacenamiento ==="
& $vbox createvm --name=$VmName --ostype=Debian13_64 --register
& $vbox storagectl $VmName --name "SATA" --add sata --controller IntelAhci
& $vbox createmedium disk --filename $diskPath --size 8192 --format VDI
& $vbox storageattach $VmName --storagectl "SATA" --port 0 --device 0 --type hdd --medium $diskPath
& $vbox storageattach $VmName --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium emptydrive

Write-Output "=== $VmName : modifyvm (fase 1: solo NAT) ==="
& $vbox modifyvm $VmName --memory 2048 --cpus 1 --ioapic off --paravirtprovider none `
    --nic1 nat --audio-driver none --boot1 disk --boot2 dvd --boot3 none --boot4 none
& $vbox modifyvm $VmName --natpf1 "ssh,tcp,127.0.0.1,$NatSshPort,,22"
& $vbox modifyvm $VmName --nat-localhostreachable1 on

Write-Output "=== $VmName : instalacion desatendida ==="
& $vbox unattended install $VmName --iso=$Iso --user=lab --user-password=$Password `
    --full-user-name="Lab User" --hostname="$VmName.labnet" --no-install-additions `
    --package-selection-adjustment=minimal --script-template=$preseedTemplate --start-vm=headless

if (-not (Wait-SshWithRetries 3 "fase 1")) {
    Write-Output "=== $VmName : FALLO - sin SSH tras la instalacion ==="
    exit 1
}

Write-Output "=== $VmName : anadiendo NIC2 (labnet) ==="
& $vbox controlvm $VmName poweroff
Start-Sleep -Seconds 5
& $vbox modifyvm $VmName --nic2 hostonly --host-only-adapter2 $HostOnlyIf --cable-connected2 on
& $vbox startvm $VmName --type headless

if (-not (Wait-SshWithRetries 4 "fase 2")) {
    Write-Output "=== $VmName : FALLO - sin SSH tras anadir NIC2 ==="
    exit 1
}
Write-Output "=== $VmName : LISTA (falta lab/set_static_ip.py) ==="
exit 0
