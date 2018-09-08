[CmdletBinding()]
Param(
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$DiskId
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

# Get rid of any existing storage spaces pools
Update-StorageProviderCache
$ExistingPools = Get-StoragePool | Where-Object { $_.IsPrimordial -eq $false } 
$ExistingPools | Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
$ExistingPools | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
$ExistingPools | Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue

# Clears any lingering storage spaces data and metadata, leaves OS volume intact
Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue 

if ($DiskId -ne $null -and $DiskId.Length -gt 0)
{
	$DataDisks = Get-Disk | Where-Object { $_.Number -in $DiskId }
}
else
{
	$DataDisks = Get-Disk | Where-Object { $_.Number -ne $null -and $_.IsBoot -ne $true -and $_.IsSystem -ne $true }    
}

$DataDisks | Where-Object {$_.PartitionStyle -ne "RAW" } | ForEach-Object {
	$_ | Set-Disk -IsOffline $false
    $_ | Set-Disk -IsReadOnly $false
    $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
    $_ | Set-Disk -IsReadOnly $true
    $_ | Set-Disk -IsOffline $true
}