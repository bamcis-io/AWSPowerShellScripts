[CmdletBinding(DefaultParameterSetName = "PhysicalDisk")]
Param(
	[Parameter(Mandatory = $true, Position = 0)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Name,

	[Parameter(Mandatory = $true, Position = 1)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Resource,

	[Parameter(Mandatory = $true, ParameterSetName = "PhysicalDisk")]
	[ValidateNotNullOrEmpty()]
	[System.String]$DiskName,

	[Parameter(Mandatory = $true, ParameterSetName = "Largest")]
	[Switch]$UseLargest,

	[Parameter()]  
	[Switch]$EncryptData,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$FullAccess,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$ChangeAccess
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

Function Update-UserName {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$Username,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$DomainName
	)

	Begin {}

	Process {
		if (-not $Username.Contains("\"))
		{
			$Username = "$($DomainName.Split(".")[0])\$Username"
		}

		Write-Output -InputObject $Username
	}

	End {

	}
}

[Microsoft.FailoverClusters.PowerShell.ClusterResource[]]$Disks = Get-ClusterGroup -Name $Resource | Get-ClusterResource | Where-Object {$_.ResourceType -eq "Physical Disk" }

if (-not [System.String]::IsNullOrEmpty($DiskName))
{
	$Disks = $Disks | Where-Object {$_.Name -ieq $DiskName} # This should just be 1 disk
}

$Options = @()

foreach ($ClusterDisk in $Disks)
{
    $Partition = Get-CimInstance -Namespace "root/mscluster" -ClassName MSCluster_Resource -Filter "Id = '$($ClusterDisk.Id)'" | 
		Get-CimAssociatedInstance -ResultClassName "MSCluster_Disk" | 
		Get-CimAssociatedInstance -ResultClassName "MSCluster_DiskPartition"

    $Options += [PSCustomObject]@{DiskId = $ClusterDisk.Id; Name = $ClusterDisk.Name; Partition = $Partition }
}

if ($UseLargest)
{
	$Part = $Options | Sort-Object -Property {$_.Partition.FreeSpace} -Descending | Select-Object -First 1
}
else
{
	$Part = $Options | Select-Object -First 1
}

$Drive = "$($Part.Partition.Path)\"

if (-not (Test-Path -Path $Drive))
{
	throw New-Object -TypeName System.InvalidOperationException("The current node, $env:COMPUTERNAME, does not own $Drive.")
}

[System.String]$Path = "$Drive$Name"

if ((Test-Path -Path $Path) -and [System.IO.File]::Exists($Path))
{
	throw New-Object -TypeName System.ArgumentException("The calculated path, $Path, is a file that already exists. Specify a directory location.")
}
elseif(-not (Test-Path -Path $Path))
{
	New-Item -Path $Path -ItemType Directory | Out-Null
}

[System.Collections.Hashtable]$Splat = @{}
$DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain

if ($FullAccess -ne $null -and $FullAccess.Count -gt 0)
{
	$Splat.Add("FullAccess", $FullAccess)

	$Acl = Get-Acl -Path $Path

	foreach ($Item in $FullAccess)
	{
		$Identity = Update-UserName -Username $Item -DomainName $DomainName

		[System.Security.AccessControl.FileSystemAccessRule]$Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule(
			$Identity,
			[System.Security.AccessControl.FileSystemRights]::FullControl,
			@([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
			[System.Security.AccessControl.PropagationFlags]::None,
			[System.Security.AccessControl.AccessControlType]::Allow
		)
		$Acl.AddAccessRule($Ace)
	}

	Set-Acl -Path $Path -AclObject $Acl
}

if ($ChangeAccess -ne $null -and $ChangeAccess.Count -gt 0)
{
	$Splat.Add("ChangeAccess", $ChangeAccess)

	$Acl = Get-Acl -Path $Path

	foreach ($Item in $ChangeAccess)
	{
		$Identity = Update-UserName -Username $Item -DomainName $DomainName

		[System.Security.AccessControl.FileSystemAccessRule]$Ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule(
			$Identity,
			[System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
			@([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
			[System.Security.AccessControl.PropagationFlags]::None,
			[System.Security.AccessControl.AccessControlType]::Allow
		)
		$Acl.AddAccessRule($Ace)
	}

	Set-Acl -Path $Path -AclObject $Acl
}

New-SmbShare -Path $Path -Name $Name -EncryptData:$EncryptData -ContinuouslyAvailable $true -ScopeName $Resource @Splat