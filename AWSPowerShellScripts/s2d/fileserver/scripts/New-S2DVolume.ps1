[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true, Position = 0)]
	[ValidateNotNullOrEmpty()]
	[System.String]$FriendlyName,

	[Parameter(Mandatory = $true, Position = 1)]
	[ValidateNotNullOrEmpty()]
	[System.String]$StoragePoolFriendlyName,

	[Parameter(Mandatory = $true, Position = 2)]
    [ValidateSet("CSVFS_NTFS", "CSVFS_ReFS")]
	[String]$FileSystem,

	[Parameter(Position = 3)]
	[ValidateRange(1, 35184372088832)] # Max is 32TB
	[System.Int64]$Size
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

if ($Size -le 32TB)
{
	[System.Collections.Hashtable]$Splat = @{}

	if ($PSBoundParameters.ContainsKey("Size"))
	{
		$Splat.Add("Size", $Size)
	}
	else
	{
		$Splat.Add("UseMaximumSize", $true)
	}

	New-Volume -FriendlyName $FriendlyName -FileSystem $FileSystem -StoragePoolFriendlyName $StoragePoolFriendlyName @Splat
	(Get-ClusterSharedVolume).Name = $FriendlyName
}
else
{
	Write-Warning -Message "Volumes in S2D are limited to 32TB, the specified size $Size is over that capacity."
}