[CmdletBinding()]
Param(
	[Parameter()]
	[ValidatePattern("^\\\\(?:[a-zA-Z0-9].?)+\\(?:(?:[-a-zA-Z0-9_.])+\\?)+\`$?$")]
	[System.String]$FileShare
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

[System.Collections.Hashtable]$Splat = @{}

if ([System.String]::IsNullOrEmpty($FileShare))
{
	$Splat.Add("NoWitness", $true) # Node majority
}
else
{
	$Splat.Add("FileShareWitness", $FileShare) # Node and file share majority
}

Set-ClusterQuorum @Splat