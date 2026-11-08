<#
.SYNOPSIS
  Creates the AD purple team lab on Hyper-V: an internal LabNet switch plus DC01, WS01,
  optional WS02, and optional Kali.

.DESCRIPTION
  Prerequisites (one time, then reboot):
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

  Network: "LabNet" is an Internal switch. VMs can reach each other and the host
  (10.10.10.1) but not your home LAN or the internet.

  Safe to re-run: existing switch, IP, and VMs are skipped.

.EXAMPLE
  .\New-LabVMs.ps1 -ServerIso D:\ISO\server2022.iso -ClientIso D:\ISO\win11ent.iso -KaliVhdx D:\kali\kali.vhdx

.EXAMPLE
  .\New-LabVMs.ps1 -ServerIso D:\ISO\server2022.iso -ClientIso D:\ISO\win11ent.iso -IncludeWS02
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServerIso,
    [Parameter(Mandatory)][string]$ClientIso,
    [string]$KaliVhdx,
    [string]$LabRoot = 'C:\HyperV\ADLab',
    [string]$SwitchName = 'LabNet',
    [switch]$IncludeWS02
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
    throw 'Hyper-V is not enabled. Run: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All, then reboot.'
}
foreach ($iso in @($ServerIso, $ClientIso)) {
    if (-not (Test-Path $iso)) { throw "ISO not found: $iso" }
}
New-Item -ItemType Directory -Path $LabRoot -Force | Out-Null

# --- Network -------------------------------------------------------------------
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Write-Host "Created internal switch $SwitchName"
}
$hostAdapter = "vEthernet ($SwitchName)"
if (-not (Get-NetIPAddress -InterfaceAlias $hostAdapter -IPAddress 10.10.10.1 -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceAlias $hostAdapter -IPAddress 10.10.10.1 -PrefixLength 24 | Out-Null
    Write-Host "Host is 10.10.10.1 on $SwitchName"
}

# --- Windows VMs ---------------------------------------------------------------
# WS VMs start at 4 GB because the Windows 11 installer requires it.
# After setup, lower them: Set-VMMemory -VMName WS01 -StartupBytes 2560MB
$windowsVMs = @(
    @{ Name = 'DC01'; MemoryMB = 3072; DiskGB = 60; Iso = $ServerIso; Tpm = $false }
    @{ Name = 'WS01'; MemoryMB = 4096; DiskGB = 64; Iso = $ClientIso; Tpm = $true }
)
if ($IncludeWS02) {
    $windowsVMs += @{ Name = 'WS02'; MemoryMB = 4096; DiskGB = 64; Iso = $ClientIso; Tpm = $true }
}

foreach ($vm in $windowsVMs) {
    if (Get-VM -Name $vm.Name -ErrorAction SilentlyContinue) {
        Write-Warning "$($vm.Name) already exists, skipping"
        continue
    }

    $vhdPath = Join-Path $LabRoot "$($vm.Name)\$($vm.Name).vhdx"
    New-VM -Name $vm.Name -Generation 2 -Path $LabRoot `
        -MemoryStartupBytes ($vm.MemoryMB * 1MB) `
        -NewVHDPath $vhdPath -NewVHDSizeBytes ($vm.DiskGB * 1GB) `
        -SwitchName $SwitchName | Out-Null

    Set-VMProcessor -VMName $vm.Name -Count 2
    Set-VMMemory -VMName $vm.Name -DynamicMemoryEnabled $false
    Set-VM -Name $vm.Name -AutomaticCheckpointsEnabled $false -CheckpointType Standard

    $dvd = Add-VMDvdDrive -VMName $vm.Name -Path $vm.Iso -Passthru
    Set-VMFirmware -VMName $vm.Name -FirstBootDevice $dvd

    if ($vm.Tpm) {
        Set-VMKeyProtector -VMName $vm.Name -NewLocalKeyProtector
        Enable-VMTPM -VMName $vm.Name
    }
    Write-Host "Created $($vm.Name) ($($vm.MemoryMB) MB, $($vm.DiskGB) GB disk)"
}

# --- Kali (prebuilt Hyper-V image) ---------------------------------------------
if ($KaliVhdx) {
    if (Get-VM -Name 'KALI' -ErrorAction SilentlyContinue) {
        Write-Warning 'KALI already exists, skipping'
    }
    elseif (-not (Test-Path $KaliVhdx)) {
        throw "Kali VHDX not found: $KaliVhdx"
    }
    else {
        $kaliDir = Join-Path $LabRoot 'KALI'
        New-Item -ItemType Directory -Path $kaliDir -Force | Out-Null
        $kaliDisk = Join-Path $kaliDir 'kali.vhdx'
        Copy-Item -Path $KaliVhdx -Destination $kaliDisk

        New-VM -Name 'KALI' -Generation 2 -Path $LabRoot -MemoryStartupBytes 2GB `
            -VHDPath $kaliDisk -SwitchName $SwitchName | Out-Null
        Set-VMProcessor -VMName 'KALI' -Count 2
        Set-VMMemory -VMName 'KALI' -DynamicMemoryEnabled $false
        Set-VMFirmware -VMName 'KALI' -EnableSecureBoot Off
        Set-VM -Name 'KALI' -AutomaticCheckpointsEnabled $false -CheckpointType Standard
        Write-Host 'Created KALI (2048 MB)'
    }
}

Write-Host ''
Write-Host 'Next: vmconnect localhost DC01, then Start-VM DC01.'
Write-Host 'Press a key quickly at "Press any key to boot from CD or DVD".'
