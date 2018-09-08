[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true, Position = 0)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Name,

	[Parameter(Mandatory = $true, Position = 1)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Path,

	[Parameter()]  
	[Switch]$EncryptData
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

New-SmbShare -Path $Path -Name $Name -EncryptData:$EncryptData -ContinuouslyAvailable $true