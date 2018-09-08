[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$Volume,

	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$Path,

	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$Name,
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$CSV = Get-ClusterSharedVolume -Name $Volume

if (-not (Test-Path -Path $Path))
{
	New-Item -Path $Path -ItemType Directory
}

New-SmbShare -Name $Name -Path $Path -EncryptData $true -ContinuouslyAvailable $true 