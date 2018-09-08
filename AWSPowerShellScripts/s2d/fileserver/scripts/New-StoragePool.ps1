[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$StoragePoolFriendlyName
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$PhysicalDisks = Get-PhysicalDisk -CanPool $true
New-StoragePool -StorageSubSystemFriendlyName *cluster* -FriendlyName $StoragePoolFriendlyName -PhysicalDisks $PhysicalDisks -EnclosureAwareDefault $false