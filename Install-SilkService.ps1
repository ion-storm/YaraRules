# Why reinvent the wheel? Roberto did a nice job with this script, lets give him proper credit and add/remove some stuff
# Author(s): Roberto Rodriguez (@Cyb3rWard0g) & @ionstorm
# License: GPL-3.0

# References:
# https://github.com/fireeye/SilkService
# https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#version_table

write-host "[+] Processing SilkService Installation.."

$Url = "https://github.com/fireeye/SilkETW/releases/download/v0.8/SilkETW_SilkService_v8.zip"
$sPath = "C:\Program Files\SilkService\"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
(new-object System.Net.WebClient).DownloadFile("$Url",'C:\Windows\Temp\SilkService.zip')

# Unzip file
expand-archive -path C:\Windows\Temp\SilkService.zip -DestinationPath "$sPath"
if (!(Test-Path "$sPath")) { Write-Error "$File was not decompressed successfully" -ErrorAction Stop }

#Installing Dependencies
#.NET Framework 4.5	All Windows operating systems: 378389
$DotNetDWORD = 378388
$DotNet_Check = Get-ChildItem "hklm:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" | Get-ItemPropertyValue -Name Release | % { $_ -ge $DotNetDWORD }
if (!$DotNet_Check)
{
    write-Host "[!] NET Framework 4.5 or higher not installed.."
    & C:\Program Files\SilkService\v8\Dependencies\dotNetFx45_Full_setup.exe /q /passive /norestart
    start-sleep -s 5
}
$MVC_Check = Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.displayname -like "Microsoft Visual C++*" } | Select-Object DisplayName, DisplayVersion
if (!$MVC_Check)
{
    write-Host "[!] Microsoft Visual C++ not installed.."
    & C:\Program Files\SilkService\v8\Dependencies\vc2015_redist.x86.exe /q /passive /norestart
    start-sleep -s 5
}

# Download ionstorm's SilkServiceConfig & Yara Rules
$Url2 = "https://github.com/ion-storm/YaraRules/archive/refs/heads/master.zip"
$cPath = "C:\Program Files\SilkService\v8\SilkService\YaraRules\"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
(new-object System.Net.WebClient).DownloadFile("$Url2",'C:\Windows\Temp\YaraRules.zip')

# Unzip file
expand-archive -path C:\Windows\Temp\YaraRules.zip -DestinationPath "$cPath"
if (!(Test-Path "$cPath")) { Write-Error "$File was not decompressed successfully" -ErrorAction Stop }
copy-item -Path "C:\Program Files\SilkService\v8\SilkService\YaraRules\YaraRules-master\SilkServiceConfig.xml" -Destination "C:\Program Files\SilkService\v8\SilkService\" -Force -EA SilentlyContinue 
# Installing Service

write-host "[+] Creating the new SilkService service.."
New-Service -name SilkService `
    -displayName SilkService `
    -binaryPathName "C:\Program Files\SilkService\v8\SilkService\SilkService.exe" `
    -StartupType Automatic `
    -Description "This is the SilkService service to consume ETW events."

Start-Sleep -s 2

# Starting SilkService Service
write-host "[+] Starting SilkService service.."
Start-Service SilkService