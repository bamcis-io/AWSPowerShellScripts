[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true, Position = 0)]
	[ValidateNotNullOrEmpty()]
	[System.Boolean]$Enabled
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

Get-StorageSubsystem *cluster* | Set-StorageHealthSetting -Name “System.Storage.PhysicalDisk.AutoReplace.Enabled” -Value ($Enabled.ToString())