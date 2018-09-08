[CmdletBinding()]
Param(
	[Parameter(Position = 0)]
	[ValidateSet("NTFS", "ReFS", "exFAT", "FAT32", "FAT")]
	[System.String]$FileSystem = "NTFS",

	[Parameter(Position = 1)]
	[ValidateSet("GPT", "MBR")]
	[System.String]$PartitionStyle = "GPT",

	[Parameter()]
	[Switch]$EnableTrim
)

Function Get-EC2InstanceMetadata {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[System.String]$UrlFragment
	)

	Begin {}

	Process {
		$InstanceMetadataUrl = "http://169.254.169.254/latest/$UrlFragment"
		[Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri $InstanceMetadataUrl -ErrorAction SilentlyContinue
		
		if ($Response -eq $null -or $Response.StatusCode -ne 200)
		{
			throw (New-Object -TypeName System.Exception("The result from $InstanceMetadataUrl was empty."))
		}
		
		Write-Output -InputObject $Response.Content
	}

	End {}
}

Function Get-EC2BlockDeviceMapping {
	[CmdletBinding()]
	Param(
	)

	Begin {}

	Process {
		[PSCustomObject[]]$BDMs = @()
		$UrlFragment = "meta-data/block-device-mapping/"
		[System.String[]]$Disks = (Get-EC2InstanceMetadata -UrlFragment $UrlFragment) -split "`n"

		foreach ($Disk in $Disks | Where-Object {$_ -match "ebs|ephemeral|root"})
		{
			$MountPoint = Get-EC2InstanceMetadata -UrlFragment (Join-Path -Path $UrlFragment -ChildPath $Disk)
			
			$BDMs += [PSCustomObject]@{"DiskName"= $Disk; "MountPoint" = $MountPoint; IsEphemeral = ($Disk -match "ephemeral")}
		}

		Write-Output -InputObject $BDMs
	}

	End {}
}

Function Test-EphemeralDisk {
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Int32]$DiskIndex,

        [Parameter(Mandatory = $true, Position = 1)]
        [System.Int32]$DiskSCSITargetId
    )

    $IsEphemeral = $false
    
    try
    {
        # Special check: NVMe disk is mounted before boot volume and always contains SCSITargetId 0.
        # So, DiskIndex and DiskSCSITargetId are not sufficient to identify NVMe disks. 
        # Instead, it checks whether PNPDeviceId string contains NVME.
        $Disk = Get-CimInstance -ClassName Win32_DiskDrive | Where-Object { $_.Index -eq $DiskIndex }

        if ($Disk.PNPDeviceId -like "*NVME*")
        {
            return $true
        }

        if ($script:BlockDeviceMapping -eq $null)
        {
            # BlockDriveMapping mapping is used to find if each drive is ephemeral or non-ephemeral.
            Set-Variable BlockDeviceMapping -Scope Script -Value (Get-EC2BlockDeviceMapping)

            if ($script:BlockDeviceMapping.Length -eq 0)
            {
                throw New-Object System.InvalidOperationException("Could not get the block drive mapping info from metadata")
            }
        }

        # This is to determine whether disk is ephemeral, which needs to be labeled as temporary storage.
        # BlockDeviceMapping from metadata is used to find this info.
        # But it is only applicable if the system is using Citrix PV Driver.
        $DriveName = ""

        if ($DiskIndex -eq 0)
        {
            $DriveName = "/dev/sda1"
        }
        else
        {
            $DriveName = "xvd"
            $Offset = $DiskSCSITargetId

            if ($DiskSCSITargetId -gt 25)
            {
                $Math = [Int][Math]::Floor($DiskSCSITargetId / 26)
                $Offset = $DiskSCSITargetId - (26 * $Math)
                $DriveName += [Char] (97 + ($Math - 1))
            }

            $DriveName += [Char] (97 + $Offset)
        }

        $MatchingBlockDrive = $script:BlockDeviceMapping | Where-Object { $_.MountPoint -eq $DriveName }
        if ($MatchingBlockDrive.Length -ne 0) 
        {
            $IsEphemeral = $MatchingBlockDrive[0].IsEphemeral
        }
    }
    catch
    {
        Write-Verbose -Message "Failed to test ephemeral disk: $($_.Exception.Message)"
    }

    Write-Output $IsEphemeral
}

Function Get-NextAvailableDriveLetter {
	[CmdletBinding()]
    Param(
        [Parameter()]
        [Switch]$Descending
    )

    Begin {
        [System.Char[]]$Letters = "defghijklmnopqrstuvwxyz".ToCharArray()
        [System.Char[]]$ReverseLetters = "zyxwvutsrqponmlkjihgfed".ToCharArray()
    }

    Process {
        $Set = $Letters
        if ($Descending) {
            $Set = $ReverseLetters
        }

        foreach ($Char in $Set)
        {
            if (-not (Test-Path "$Char`:\"))
            {
                Write-Output -InputObject $Char
                break
            }
        }
    }

    End {
    }
}

Function Get-DiskTrimEnabled {
    [CmdletBinding()]
	Param()

	Begin {}

	Process {
		Write-Output -InputObject ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "DisableDeleteNotification") -eq 0)
	}

	End {}
}

Function Set-DiskTrim {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.Boolean]$Enabled,

        [Parameter()]
        [Switch]$PassThru
    )

    Begin {}

    Process {
        if ($Enabled) {
            $Val = 0
        }
        else {
            $Val = 1
        }

        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "DisableDeleteNotification" -Value $Val

        if ($PassThru)
        {
            Write-Output -InputObject $Val
        }
    }

    End {}
}

try 
{
	Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
	$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
	

	Stop-Service -Name ShellHWDetection -Force -Confirm:$false

	$EphemeralCounter = 0

	$WasTrimEnabled = Get-DiskTrimEnabled
	Set-DiskTrim -Enabled $EnableTrim

	foreach ($Disk in Get-Disk | Where-Object {$_.OperationalStatus -eq "Offline" -or $_.PartitionStyle -eq "RAW"})
	{
		$SCSITargetId = Get-CimInstance -ClassName Win32_DiskDrive -Filter "Index = $($Disk.Number)" | Select-Object -ExpandProperty SCSITargetId
		$Disk | Set-Disk -IsOffline $false
		$Disk | Set-Disk -IsReadOnly $false
		
		if ($Disk.PartitionStyle -eq "RAW")
		{
			$PartitionSplat = @{}

			switch ($PartitionStyle)
			{
				"GPT" {
					$PartitionSplat.Add("GptType", "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}")
				}
				"MBR" {
					$PartitionSplat.Add("MbrType", "IFS")
					$PartitionSplat.Add("IsActive", $true)
				}
			}

			[System.Collections.Hashtable]$FormatSplat = @{}

			if ($SCSITargetId -ne $null -and (Test-EphemeralDisk -DiskIndex $Disk.Number -DiskSCSITargetId $SCSITargetId))
			{
				$FormatSplat.Add("NewFileSystemLabel", "Temporary Storage $EphemeralCounter")
				$DriveLetter = Get-NextAvailableDriveLetter -Descending
			}
			else
			{
				$DriveLetter = Get-NextAvailableDriveLetter
			}

			$Disk | 
				Initialize-Disk -PartitionStyle $PartitionStyle -Confirm:$false -PassThru | 
				New-Partition -UseMaximumSize -DriveLetter $DriveLetter @PartitionSplat | 
				Format-Volume -FileSystem $FileSystem -Confirm:$false @FormatSplat			
		}
	}

	if (-not $EnableTrim)
	{
		Set-DiskTrim -Enabled $WasTrimEnabled
	}
}
catch [Exception]
{
	Write-Warning -Message $_.Exception.Message
}
finally 
{
	Start-Service -Name ShellHWDetection -Confirm:$false -ErrorAction SilentlyContinue
}