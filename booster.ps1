Add-Type -AssemblyName System.Windows.Forms 
Clear-Host

function Check-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script must be run with administrator privileges" -ForegroundColor Red
        Start-Sleep -Seconds 2
        exit
    }
}

function Install-PSWindowsUpdateModule {
    if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable)) {
        Install-Module -Name PSWindowsUpdate -Force
    }
}
function Modify-Registry {
    param (
        [string]$keyPath,
        [string]$valueName,
        [int]$valueData
    )

    try {
        $key = Get-Item -LiteralPath "HKLM:\$keyPath" -ErrorAction Stop
    } catch {
        $key = New-Item -Path "HKLM:\$keyPath" -Force
    }

    try {
        Set-ItemProperty -Path $key.PSPath -Name $valueName -Value $valueData
        Write-Output "Registry key and DWORD value set successfully."
    } catch {
        Write-Error "Error setting registry DWORD value: $_"
    }
}

function Modify-RegistryString {
    param (
        [string]$keyPath,
        [string]$valueName,
        [string]$valueData
    )

    try {
        $key = Get-Item -LiteralPath "HKCU:\$keyPath" -ErrorAction Stop
    } catch {
        $key = New-Item -Path "HKCU:\$keyPath" -Force
    }

    try {
        Set-ItemProperty -Path $key.PSPath -Name $valueName -Value $valueData
        Write-Output "Registry key and String value set successfully."
    } catch {
        Write-Error "Error setting registry String value: $_"
    }
}
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
Check-Administrator
Install-PSWindowsUpdateModule

Modify-Registry -keyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -valueName "SearchOrderConfig" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Control" -valueName "WaitToKillServiceTimeout" -valueData 2000
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Control\Session Manager\Power" -valueName "HiberbootEnabled" -valueData 0
Modify-Registry -keyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -valueName "NetworkThrottlingIndex" -valueData 4294967295
Modify-Registry -keyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -valueName "SystemResponsiveness" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -valueName "autodisconnect" -valueData 4294967295
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -valueName "Size" -valueData 1
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -valueName "EnableOplocks" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -valueName "IRPStackSize" -valueData 32
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -valueName "SharingViolationDelay" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -valueName "SharingViolationRetries" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -valueName "TcpAckFrequency" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -valueName "TCPNoDelay" -valueData 0
Modify-Registry -keyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -valueName "GPU Priority" -valueData 8
Modify-Registry -keyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -valueName "Priority" -valueData 6
Modify-Registry -keyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -valueName "Scheduling Category" -valueData "High"
Modify-Registry -keyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -valueName "SFIO Priority" -valueData "High"
Modify-Registry -keyPath "SOFTWARE\Policies\Microsoft\Windows\Psched" -valueName "NonBestEffortLimit" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -valueName "HwSchMode" -valueData 2
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -valueName "TcpAckFrequency" -valueData 1
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -valueName "TCPNoDelay" -valueData 1
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -valueName "TCPDelAckTicks" -valueData 1
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -valueName "TCPNoDelay" -valueData 1
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" -valueName "TcpAckFrequency" -valueData 1
Modify-Registry -keyPath "SOFTWARE\Microsoft\MSMQ\Parameters" -valueName "TCPNoDelay" -valueData 1
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -valueName "LocalPriority" -valueData 4
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -valueName "HostsPriority" -valueData 5
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -valueName "DnsPriority" -valueData 6
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -valueName "NetbtPriority" -valueData 7
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -valueName "autodisconnect" -valueData 4294967295
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -valueName "Size" -valueData 3
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -valueName "EnableOplocks" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -valueName "IRPStackSize" -valueData 32
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -valueName "EnableOplocks" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -valueName "SharingViolationDelay" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" -valueName "SharingViolationRetries" -valueData 1
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Control\PriorityControl" -valueName "ConvertibleSlateMode" -valueData 0
Modify-Registry -keyPath "SYSTEM\CurrentControlSet\Control\PriorityControl" -valueName "Win32PrioritySeparation" -valueData 56
Modify-RegistryString -keyPath "System\GameConfigStore" -valueName "GameDVR_DXGIHonorFSEWindowsCompatible" -valueData "0"
Modify-RegistryString -keyPath "System\GameConfigStore" -valueName "GameDVR_EFSEFeatureFlags" -valueData "0"
Modify-RegistryString -keyPath "System\GameConfigStore" -valueName "GameDVR_Enable" -valueData "1"
Modify-RegistryString -keyPath "System\GameConfigStore" -valueName "GameDVR_FSEBehaviorMode" -valueData "2"
Modify-RegistryString -keyPath "System\GameConfigStore" -valueName "GameDVR_HonorUserFSEBehaviorMode" -valueData "0"


Remove-Item -Path *.log -Recurse -Force
Clear-DnsClientCache
netsh int tcp set global autotuninglevel=disabled
netsh winsock reset
pnputil /add-driver * /install /reboot
$adapterIndex = Get-NetAdapter | Select-Object -ExpandProperty InterfaceDescription -First 2 | Select-Object -Last 1
Set-NetAdapterAdvancedProperty -InterfaceIndex $adapterIndex -DisplayName "Speed" -DisplayValue "1 Gbps"
netsh int tcp set heuristics disabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set supplemental custom congestionprovider=ctcp
netsh interface tcp set heuristics disabled
Clear-DnsClientCache
Import-Module -Name PSWindowsUpdate
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll
winget upgrade --all
Remove-Item -Path $env:TEMP -Recurse -Force
New-Item -Path $env:TEMP -ItemType Directory
takeown /f $env:TEMP -recurse -force
takeown /f "C:\Windows\Temp" /r /a
Remove-Item -Path "C:\Windows\Temp" -Recurse -Force
New-Item -Path "C:\Windows\Temp" -ItemType Directory
cleanmgr
msconfig
foreach ($F in Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") {
    DISM /Online /NoRestart /Add-Package:"$F"
}

foreach ($F in Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") {
    DISM /Online /NoRestart /Add-Package:"$F"
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched -Name NonBestEffortLimit -Value 0
gpupdate /force
sfc /scannow
Dism /Online /Cleanup-Image /ScanHealth
Dism /Online /Cleanup-Image /CheckHealth
Repair-WindowsImage -Online -RestoreHealth
