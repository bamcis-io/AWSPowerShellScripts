[CmdletBinding()]
Param(
	[Parameter()]
	[System.String]$ClusterName = [System.String]::Empty,

	[Parameter()]
	[System.UInt64]$SizeInMB = 2048
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$Capacity = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory) / 1MB

if ($SizeInMB -lt $Capacity)
{
	[System.Collections.Hashtable]$Splat = @{}

	if (-not [System.String]::IsNullOrEmpty($ClusterName))
	{
		$Splat.Add("Name", $ClusterName)
	}

	(Get-Cluster @Splat).BlockCacheSize = $Size
}
else
{
	Write-Warning -Message "The specified size $SizeInMB is larger than the available memory, $Capacity."
}