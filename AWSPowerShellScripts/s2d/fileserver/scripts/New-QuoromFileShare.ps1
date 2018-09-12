[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true, Position = 0)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Path,

	[Parameter(Mandatory = $true, Position = 1)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Name,

	[Parameter()]
	[System.String[]]$FullAccess,

	[Parameter()]
	[System.String[]]$ChangeAccess
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

if ((Test-Path -Path $Path) -and [System.IO.File]::Exists($Path))
{
	throw New-Object -TypeName System.ArgumentException("The provided path, $Path, is a file that already exists. Specify a directory location.")
}
elseif(-not (Test-Path -Path $Path))
{
	New-Item -Path $Path -ItemType Directory | Out-Null
}

[System.Collections.Hashtable]$Splat = @{}
$DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain

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

New-SmbShare -Path $Path -Name $Name -EncryptData $true @Splat 