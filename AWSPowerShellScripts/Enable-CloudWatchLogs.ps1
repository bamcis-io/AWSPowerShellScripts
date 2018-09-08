
<#
	.SYNOPSIS
		Sets up CloudWatch Logs for the instance.

	.DESCRIPTION
		Sets up CloudWatch Logs for the instance via either a config stored in S3 or an SSM document.

	.PARAMETER Key
		The key of an object in S3 that is the config file.

	.PARAMTER Bucket
		The bucket that contains the config file.

	.PARAMETER SSMDocument
		The name of an existing SSM document that will configure CloudWatch Logs.

	.PARAMETER Reboot
		If specified, this indicates that the instance will be rebooted by some other means later on in order to
		make the updates to the CloudWatch Logs config effective. Otherwise, the script will use a scheduled task
		to initiate a restart of the SSMAgent or EC2Config service.
	
	.EXAMPLE
		Set-DNSServers -DNSServers 192.168.1.1,192.168.1.2

	.INPUTS
		System.String[]

	.OUTPUTS
		None

	.NOTES
		AUTHOR: Michael Haken
		LAST UPDATE: 4/15/2017
#>
[CmdletBinding(DefaultParameterSetName = "LocalConfig")]
Param(
    [Parameter(ParameterSetName = "LocalConfig")]
    [ValidateNotNullOrEmpty()]
    [System.String]$Key,

    [Parameter(ParameterSetName = "LocalConfig")]
    [ValidateNotNullOrEmpty()]
    [System.String]$Bucket,

    [Parameter(Mandatory = $true, ParameterSetName = "SSM")]
    [ValidateNotNullOrEmpty()]
    [System.String]$SSMDocument,

    [Parameter()]
    [switch]$Reboot,

	[Parameter()]
	[ValidateNotNull()]
	[Amazon.RegionEndpoint]$Region,

	[Parameter()]
	[ValidateNotNull()]
	[System.String]$ProfileName = [System.String]::Empty,

	[Parameter()]
	[ValidateNotNull()]
	[System.String]$AccessKey = [System.String]::Empty,

	[Parameter()]
	[ValidateNotNull()]
	[System.String]$SecretKey = [System.String]::Empty,

	[Parameter()]
	[ValidateNotNull()]
	[System.String]$SessionToken = [System.String]::Empty,

	[Parameter()]
	[ValidateNotNull()]
	[Amazon.Runtime.AWSCredentials]$Credential,

	[Parameter()]
	[ValidateNotNull()]
	[System.String]$ProfileLocation = [System.String]::Empty
)

#[System.Collections.Hashtable]$AWSSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

try
{
    [System.String]$CloudWatchLogConfigDestination = "$env:ProgramFiles\Amazon\Ec2ConfigService\Settings\AWS.EC2.Windows.CloudWatch.json"
    [System.String]$EC2SettingsFile="$env:ProgramFiles\Amazon\Ec2ConfigService\Settings\Config.xml"

    $AWSSoftware = Get-AWSSoftware
    $SSMSoftware = $AWSSoftware | Where-Object -FilterScript {$_.DisplayName -eq "Amazon SSM Agent"} | Select-Object -First 1
    $EC2ConfigSW = $AWSSoftware | Where-Object -FilterScript {$_.DisplayName -eq "EC2ConfigService"} | Select-Object -First 1

    if ($SSMSoftware -ne $null -and -not [System.String]::IsNullOrEmpty($SSMDocument))
    {
        Write-Log -Message "Using SSM to configure CloudWatch."
        
        $ServiceName = "AmazonSSMAgent"

        $InstanceId = Get-EC2InstanceId

        try
        {
            Write-Log -Message "Updating SSM agent to latest."
            New-SSMAssociation -InstanceId $InstanceId -Name "AWS-UpdateSSMAgent" -Force | Out-Null
        }
        catch [Amazon.SimpleSystemsManagement.Model.AssociationAlreadyExistsException]
        {
            Write-Log -Message "The AWS-UpdateSSMAgent association already exists."
        }

        try
        {
            Write-Log -Message "Associating CloudWatch SSM Document $SSMDocument."
            New-SSMAssociation -Target  @{Key="instanceids"; Values=@($InstanceId)} -Name $SSMDocument -Parameter @{"status" = "Enabled"} -Force | Out-Null
        }
        catch [Amazon.SimpleSystemsManagement.Model.AssociationAlreadyExistsException]
        {
            Write-Log -Message "The $CloudWatchSSMDocument association already exists."
        }
    }
    elseif ($EC2ConfigSW -ne $null)
    {
        $ServiceName = "EC2Config"

        Write-Log -Message "EC2Config Service Version $($EC2ConfigSW.DisplayVersion)"

        if (-not [System.String]::IsNullOrEmpty($Bucket) -and -not [System.String]::IsNullOrEmpty($Key))
        {
            Write-Log -Message "Downloading CloudWatch configuration file."

            Copy-S3Object -BucketName $Bucket -Key $Key -LocalFile $CloudWatchLogConfigDestination -Force
        }

        if (-not (Test-Path -Path $CloudWatchLogConfigDestination))
        {
            $Val = @"
{
  "IsEnabled": true,
  "EngineConfiguration": {
    "PollInterval": "00:00:05",
    "Components": [
    ],
    "Flows": {
      "Flows": [
      ]
    }
  }
}
"@
           Set-Content -Path $CloudWatchLogConfigDestination -Value $Val -Force
        }

        # Version is 0xMMmmBBB
        [System.String]$Hex = $EC2ConfigSW.Version.ToString("X")

        # The major and minor values are stored little endian, so they need to be flipped
        # The build number is stored big endian
        $Hex = $Hex.Substring(1, 1) + $Hex.Substring(0, 1)
        $Major = [System.Int32]::Parse($Hex.Substring(0, 2), [System.Globalization.NumberStyles]::HexNumber)

        # For EC2Config less than version 4, enabling CloudWatch has to be done in the XML config
        if ($Major -lt 4)
        {
            Write-Log -Message "Ensuring the IsEnabled property isn't present in the config file."

            [PSCustomObject]$Obj = ConvertFrom-Json -InputObject (Get-Content -Path $CloudWatchLogConfigDestination -Raw)
        
            if ($Obj.Properties.Name -icontains "IsEnabled")
            {
                $Obj.Properties.Remove("IsEnabled")
                Set-Content -Path $CloudWatchLogConfigDestination -Value (ConvertTo-Json -InputObject $Obj) -Force
            }

            Write-Log -Message "Retrieving EC2Config settings file."

            [System.Xml.XmlDocument]$Xml = Get-Content -Path $EC2SettingsFile
            $Xml.Get_DocumentElement().Plugins.ChildNodes | Where-Object {$_.Name -eq "AWS.EC2.Windows.CloudWatch.PlugIn"} | ForEach-Object { $_.State = "Enabled"}

            Write-Log -Message "Saving updated settings file."
            $Xml.Save($EC2SettingsFile)
        }
        # Othwerwise it is done in the CloudWatch json file and SSM uses it to deliver logs and metrics
        else
        {
            Write-Log -Message "Ensuring the IsEnabled property is present and set to true in the config file."

            [PSCustomObject]$Obj = ConvertFrom-Json -InputObject (Get-Content -Path $CloudWatchLogConfigDestination -Raw)
        
            $Obj.IsEnabled = $true
            Set-Content -Path $CloudWatchLogConfigDestination -Value (ConvertTo-Json -InputObject $Obj) -Force

            $ServiceName = "AmazonSSMAgent"
        }

        if (-not $Reboot)
        {
            try 
            {
                $RestartServiceTaskName = "Restart$ServiceName`Task"

                Write-Log -Message "Creating scheduled task to restart $ServiceName service."

                if ((Get-ScheduledTask -TaskName $RestartServiceTaskName -ErrorAction SilentlyContinue) -ne $null) 
                {
                    Unregister-ScheduledTask -TaskName $RestartServiceTaskName -Confirm:$false
                }

                $Command = @"
try {                   
    Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Executing scheduled task $RestartServiceTaskName, waiting 30 seconds for other actions to complete."
    Start-Sleep -Seconds 30
    Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Removing script file at $PSCommandPath."
    Remove-Item -Path "$PSCommandPath" -Force
    Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Restarting $ServiceName service."
    Restart-Service -Name $ServiceName -Force
    Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Unregistering scheduled task."
    Unregister-ScheduledTask -TaskName $RestartServiceTaskName -Confirm:`$false
    Add-Content -Path "$script:LogPath" -Value "[INFO] `$(Get-Date) : Successfully unregistered scheduled task, task complete."
} 
catch [Exception] {
    Add-Content -Path "$script:LogPath" -Value "[ERROR] `$(Get-Date) : `$(`$_.Exception.Message)"
    Add-Content -Path "$script:LogPath" -Value "[ERROR] `$(Get-Date) : `$(`$_.Exception.StackTrace)"
}
"@

                $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
                $EncodedCommand = [Convert]::ToBase64String($Bytes)

                $STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
                $STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
                $STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams
                $STPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
                $STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew
                   
                $ScheduledTask = Register-ScheduledTask -TaskName $RestartServiceTaskName -Action $STAction -Principal $STPrincipal -Settings $STSettings -ErrorAction Stop 
                Start-ScheduledTask -TaskName $RestartServiceTaskName
            }
            catch [Exception] 
            {
                Write-Log -Message "Error running scheduled task to restart $ServiceName service." -ErrorRecord $_ -Level ERROR
            }
        }                   
    }
    else
    {
        Write-Log -Message "The SSM Agent and the EC2Config service are both not installed, cannot configure CloudWatch." -Level WARNING
    }
}
catch [Exception]
{
    Write-Log -Message "Error configuring CloudWatch." -ErrorRecord $_ -Level ERROR
}