[CmdletBinding()]
Param(
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String]$ClusterName = [System.String]::Empty,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String]$StoragePoolFriendlyName = [System.String]::Empty,

	[Parameter()]
	[ValidateSet(8, 16, 32, 64)]
	[System.Int32]$CachePageSizeKBytes = 16,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String]$CacheDeviceModel,

	[Parameter()]
	[Switch]$NoAutoConfig
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

[System.Collections.Hashtable]$Splat = @{}

if (-not [System.String]::IsNullOrEmpty($StoragePoolFriendlyName))
{
	$Splat.Add("PoolFriendlyName", $StoragePoolFriendlyName)
}

if ($CachePageSizeKBytes -ne 16)
{
	$Splat.Add("CachePageSizeKBytes", $CachePageSizeKBytes)
}

if (-not [System.String]::IsNullOrEmpty($CacheDeviceModel))
{
	$Splat.Add("CacheDeviceModel", $CacheDeviceModel)
}

if ($NoAutoConfig)
{
	$Splat.Add("Autoconfig", $false)
}

if (-not [System.String]::IsNullOrEmpty($ClusterName))
{
	Get-Cluster -Cluster $ClusterName | Enable-ClusterStorageSpacesDirect @Splat -Confirm:$false
}
else
{
	Enable-ClusterStorageSpacesDirect @Splat -Confirm:$false
}