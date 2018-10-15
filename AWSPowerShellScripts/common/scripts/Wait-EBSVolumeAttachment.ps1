[CmdletBinding(DefaultParameterSetName = "Vol")]
Param(
	[Parameter(Position = 0, ParameterSetName = "CFN")]
	[ValidateNotNullOrEmpty()]
	[System.String]$StackName,

	[Parameter(Position = 1, ParameterSetName = "CFN")]
    [ValidateNotNull()]
	[System.String[]]$CFNLogicalVolumeIds,

	[Parameter(Position = 0, ParameterSetName = "Vol")]
	[ValidateNotNull()]
	[System.String[]]$VolumeIds = @()
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

if ($PSCmdlet.ParameterSetName -eq "CFN")
{
	if ([System.String]::IsNullOrEmpty($StackName))
	{
		$StackName = Get-EC2Tag -Filter @(
				@{ Name = "resource-id"; Values = $InstanceId},
				@{ Name = "resource-type"; Values = "instance"},
				@{ Name = "key"; Values = "aws:cloudformation:stack-name"}
			) -MaxResult 1 | Select-Object -First 1 -ExpandProperty Value
	}

	foreach ($Vol in $CFNLogicalVolumeIds)
	{
		$Counter = 0

		while ($true -and $Counter -lt 120) {
			try {
				[Amazon.CloudFormation.Model.StackResourceDetail]$Resource = Get-CFNStackResource -StackName $StackName -LogicalResourceId $Vol

				if ($Resource -eq $null -or [System.String]::IsNullOrEmpty($Resource.PhysicalResourceId))
				{
					Start-Sleep -Milliseconds 5000
				}
				else
				{
					$VolumeIds += $Resource.PhysicalResourceId
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
					Write-Warning -Message "Could not retrieve stack resource $Vol with exception: $($_.Exception.Message)"
					throw $_.Exception
				}
			}

			$Counter++
		}

		if ($Counter -ge 120)
		{
			$Message = "The wait time for volume $Vol to be created in CFN has expired, it has not been added to be awaited for."
			Write-Warning -Message $Message
			throw $Message
		}
	}
}

[System.String]$InstanceId = Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/instance-id" | Select-Object -ExpandProperty Content

$ShouldContinue = $true

if ($VolumeIds.Length -gt 0)
{
    try
    {
	    while (-not $ShouldContinue) {
		    [Amazon.EC2.Model.Volume[]]$Volumes = Get-EC2Volume -VolumeId $VolumeIds

		    # Prove that we do need to continue by finding a volume that
		    # it not attached
		    $ShouldContinue = $false

		    if ($Volumes -ne $null)
		    {
			    foreach ($Volume in $Volumes)
			    {
				    $Attachments = $Volume.Attachments | Where-Object { $_.InstanceId -ieq $InstanceId }

				    foreach ($Att in $Attachments)
				    {
					    if ($Att.State -ne [Amazon.EC2.VolumeAttachmentState]::Attached)
					    {
						    Write-Warning -Message "The volume $($Volume.VolumeId) is not attached, it is $($Att.State)."
						    # Volume is not attached, so we need to continue the loop
						    # Break out here as there's no need to continue processing
						    $ShouldContinue = $true
						    break
					    }			
				    }
			    }
		    }

		    if (-not $ShouldContinue)
		    {
			    break
		    }
		    else
		    {
			    Start-Sleep -Milliseconds 5000
		    }
	    }

	    Write-Host "The volumes $([System.String]::Join(",", $VolumeIds)) have been successfully attached."
    }
    catch [Exception] {
	    Write-Warning -Message "Could not ensure volumes are attached because of an exception: $($_.Exception.Message)"
    }
}