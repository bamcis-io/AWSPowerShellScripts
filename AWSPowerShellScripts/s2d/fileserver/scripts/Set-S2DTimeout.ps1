Param(
	[Parameter()]
	[ValidateRange(1, [System.Int32]::MaxValue)]
	[System.Int32]$Timeout = 0x7530
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spaceport\Parameters" -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spaceport\Parameters" -Name "HwTimeout" -PropertyType "DWORD" -Value $Timeout