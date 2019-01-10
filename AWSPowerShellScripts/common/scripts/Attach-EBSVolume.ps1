[CmdletBinding(DefaultParameterSetName = "Vol")]
Param(
	[Parameter(Position = 0, ParameterSetName = "CFN")]
	[ValidateNotNullOrEmpty()]
	[System.String]$StackName,

	[Parameter(Position = 1, ParameterSetName = "CFN")]
    [ValidateNotNull()]
	[System.Collections.Hashtable[]]$CFNLogicalVolumeDeviceMapping = @(),

	[Parameter(Position = 0, ParameterSetName = "Vol")]
	[ValidateNotNull()]
	[System.Collections.Hashtable[]]$VolumeDeviceMapping = @()
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

Function Put-EBSInAvailableState {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[System.String]$VolumeId
	)

	Begin {}

	Process {
		[Amazon.EC2.Model.Volume]$Volume = Get-EC2Volume -VolumeId $VolumeId

		foreach ($Attach in $Volume.Attachments)
		{
            Write-Host "Processing $($Attach.State)"

			$InstanceId = $Attach.InstanceId

			switch ($Attach.State)
			{
			    ([Amazon.EC2.VolumeAttachmentState]::Detached)
				{
					# Do nothing
					break
				}
				([Amazon.EC2.VolumeAttachmentState]::Detaching)
				{
					# Wait for volume to finish detaching

					while ($Attach.State -eq ([Amazon.EC2.VolumeAttachmentState]::Detaching))
					{
						Start-Sleep -Seconds 5
						
						$Attach = Get-EC2Volume -Filter @(
							@{ "volume-id" = $Volume.VolumeId },
							@{ "attachment.instance-id" = $InstanceId }
						) -MaxResult 1 | Select-Object -First 1
					}

					break
				}
				([Amazon.EC2.VolumeAttachmentState]::Attached)
				{
                    Write-Host "Detaching attached volume $($Volume.VolumeId) $($Attach.Device) $InstanceId"
					# Detach volume

					[Amazon.EC2.Model.VolumeAttachment]$Dismount = Dismount-EC2Volume `
						-InstanceId $InstanceId `
						-VolumeId $Volume.VolumeId `
						-Device $Attach.Device `
						-ForceDismount $true `
						-Force

                    while ($Attach.State -eq [Amazon.EC2.VolumeAttachmentState]::Detached)
					{
						Start-Sleep -Seconds 5

                        $Attach = Get-EC2Volume -Filter @(
							@{ "volume-id" = $Volume.VolumeId },
							@{ "attachment.instance-id" = $InstanceId }
						) -MaxResult 1 | Select-Object -First 1
					}

					break
				}
				([Amazon.EC2.VolumeAttachmentState]::Attaching)
				{
					# Wait for volume to finish attaching, then detach

					$InstanceId = $Attach.InstanceId
					
					while ($Attach.State -ne ([Amazon.EC2.VolumeAttachmentState]::Attached))
					{
						Start-Sleep -Seconds 5
						
						$Attach = Get-EC2Volume -Filter @(
							@{ "volume-id" = $Volume.VolumeId },
							@{ "attachment.instance-id" = $InstanceId }
						) -MaxResult 1 | Select-Object -First 1
					}

					[Amazon.EC2.Model.VolumeAttachment]$Dismount = Dismount-EC2Volume `
						-InstanceId $InstanceId `
						-VolumeId $Volume.VolumeId `
						-Device $Attach.Device `
						-ForceDismount $true `
						-Force

                    while ($Attach.State -eq [Amazon.EC2.VolumeAttachmentState]::Detached)
					{
						Start-Sleep -Seconds 5
                        
                        $Attach = Get-EC2Volume -Filter @(
							@{ "volume-id" = $Volume.VolumeId },
							@{ "attachment.instance-id" = $InstanceId }
						) -MaxResult 1 | Select-Object -First 1
					}

					break
				}
				([Amazon.EC2.VolumeAttachmentState]::Busy)
				{
					while ($Attach.State -eq [Amazon.EC2.VolumeAttachmentState]::Busy)
					{
						Start-Sleep -Seconds 5
					}

					Put-EBSInAvailableState -VolumeId $Volume.VolumeId

					break
				}
			}
		}

		$Volume = Get-EC2Volume -VolumeId $VolumeId

		if ($Volume.State -ne [Amazon.EC2.VolumeState]::Available)
		{
			throw New-Object -TypeName System.Exception("The volume $($Volume.VolumeId) could not be successfully brought into an available state and is currently $($Volume.State).")
		}
	}

	End {

	}
}

[System.String]$InstanceId = Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/instance-id" | Select-Object -ExpandProperty Content

if ($PSCmdlet.ParameterSetName -eq "CFN")
{
	if ([System.String]::IsNullOrEmpty($StackName))
	{
		$StackName = Get-EC2Tag -Filter @(
				@{ Name = "resource-id"; Values = $InstanceId},
				@{ Name = "resource-type"; Values = "instance"},
				@{ Name = "key"; Values = "aws:cloudformation:stack-name"}
			) | Select-Object -First 1 -ExpandProperty Value
	}

	foreach ($Mapping in $CFNLogicalVolumeDeviceMapping)
	{
		if ($Mapping -eq $null)
		{
			$Message = "A CFN Device Mapping was null."
			Write-Warning -Message $Message
			throw New-Object -TypeName System.ArgumentNullException("Mapping")
		}

		if (-not $Mapping.ContainsKey("Device"))
		{
			$Message = "The CFN Device Mapping input $Mapping does not contain a `"Device`" key."
			Write-Warning -Message $Message
			throw $Message
		}

		if (-not $Mapping.ContainsKey("LogicalResourceId"))
		{
			$Message = "The CFN Device Mapping input $Mapping does not contain a `"LogicalResourceId`" key."
			Write-Warning -Message $Message
			throw $Message
		}

		$Counter = 0

		while ($true -and $Counter -lt 120) {
		
			try {
				[Amazon.CloudFormation.Model.StackResourceDetail]$Resource = Get-CFNStackResource -StackName $StackName -LogicalResourceId $Mapping["LogicalResourceId"]

				if ($Resource -eq $null -or [System.String]::IsNullOrEmpty($Resource.PhysicalResourceId))
				{
					Start-Sleep -Milliseconds 5000
				}
				else
				{
					$VolumeDeviceMapping += @{ "VolumeId" = $Resource.PhysicalResourceId; "Device" = $Mapping["Device"]}
					break
				}
			}
			catch [System.InvalidOperationException] {
				if ($_.Exception.Message -like "*does not exist for stack*")
				{
					Start-Sleep -Milliseconds 5000
				}
				else
				{
					Write-Warning -Message "Could not retrieve stack resource $($Mapping["LogicalResourceId"]) with exception: $($_.Exception.Message)"
					throw $_.Exception
				}
			}

			$Counter++
		}

		if ($Counter -ge 120)
		{
			$Message = "The wait time for volume $($Mapping["LogicalResourceId"]) to be created in CFN has expired, it has not been added to be awaited for."
			Write-Warning -Message $Message
			throw $Message
		}
	}
}

if ($VolumeDeviceMapping.Length -gt 0)
{
    try
    {
		[Amazon.EC2.Model.VolumeAttachment[]]$Attachments = @()

		foreach ($Volume in $VolumeDeviceMapping)
		{
			if ($Volume -eq $null)
			{
				$Message = "A Volume Device Mapping was null."
				Write-Warning -Message $Message
				throw New-Object -TypeName System.ArgumentNullException("Mapping")
			}

			if (-not $Volume.ContainsKey("Device"))
			{
				$Message = "The Volume Device Mapping input $Volume does not contain a `"Device`" key."
				Write-Warning -Message $Message
				throw $Message
			}

			if (-not $Volume.ContainsKey("VolumeId"))
			{
				$Message = "The Volume Device Mapping input $Volume does not contain a `"VolumeId`" key."
				Write-Warning -Message $Message
				throw $Message
			}

			[Amazon.EC2.Model.Volume]$Vol = Get-EC2Volume -VolumeId $Volume["VolumeId"]

			Put-EBSInAvailableState -VolumeId $Vol.VolumeId

			[Amazon.EC2.Model.VolumeAttachment]$Att = Add-EC2Volume -InstanceId $InstanceId -VolumeId $Volume["VolumeId"] -Device $Volume["Device"] -Force
			$Attachments += $Att
		}

		for ($i = 0; $i -lt $Attachments.Length; $i++)
		{
			while ($Attachments[$i].State -ne [Amazon.EC2.VolumeAttachmentState]::Attached)
			{
				Write-Warning -Message "The volume $($Attachments[$i].VolumeId) is not attached, it is $($Attachments[$i].State)."
				Start-Sleep -Seconds 5
				$Attachments[$i] = Get-EC2Volume -VolumeId $Attachments[$i].VolumeId | Select-Object -ExpandProperty Attachments | Where-Object {$_.Device -eq $Attachments[$i].Device -and $_.InstanceId -eq $Attachments[$i].InstanceId } | Select-Object -First 1
			}	
		}

	    Write-Host "The volumes $([System.String]::Join(",", ($VolumeDeviceMapping | ForEach-Object { $_.VolumeId }))) have been successfully attached to $InstanceId."
    }
    catch [Exception] {
	    Write-Warning -Message "Could not ensure volumes are attached because of an exception: $($_.Exception.Message)"
    }
}