<#PSScriptInfo
.GUID
	61396136-ee33-4d49-a913-902ad630ad1b

.VERSION 
	1.0.0

.AUTHOR
	Michael Haken

.COMPANYNAME
	bamcis.io

.COPYRIGHT
	(c) 2018 BAMCIS. All rights reserved.

.TAGS
	AWS EC2

.LICENSEURI
	https://raw.githubusercontent.com/bamcis-io/AWSPowerShellScripts/master/LICENSE

.PROJECTURI
	https://github.com/bamcis-io/AWSPowerShellScripts

.ICONURI
.EXTERNALMODULEDEPENDENCIES
	AWSPowerShell
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
	*1.0.0 - Initial Release
#>

<#
	.SYNOPSIS
		Runs common setup for AWS EC2 Windows instances.

	.DESCRIPTION
		Runs common setup actions for AWS EC2 Windows instances. For example, the script can rename the computer,
		join it to a domain, enable CloudWatch Logs, install WMF5, install CfnInit, and set DNS servers.

	.PARAMETER NewComputerName
		A new name for the computer.

	.PARAMETER BucketName
		The name of the bucket where configuration files are stored.

	.PARAMETER OutputBucketName
		The bucket where the logs of this setup will be delivered. If this is not specified, the logs will just be retained locally
		on the server.

	.PARAMETER SendToCloudWatchLogs
		The logs produced during this script will be streamed to CloudWatch Logs for viewing.

	.PARAMETER CloudWatchConfig
		The json configuration for CloudWatch logs.

	.PARAMETER CloudWatchSSMDocument
		The SSM document to configure CloudWatch logs.

	.PARAMETER InstallWMF5
		Will install WMF5 if it is not already installed.

	.PARAMETER InstallCfnInit
		Will install CfnInit for use with CloudFormation.

	.PARAMETER DomainName
		The name of the domain to join this server to.

	.PARAMETER DomainJoinUsername
		The user account to use to join the server to the domain.

	.PARAMETER DomainJoinPassword
		The password associated with the user account being used to join the server to the domain.

	.PARAMETER DNSServers
		The DNS Servers to configure the server with. This should point to domain controllers if the machine
		is being domain joined and DHCP doesn't already provide this configuration.

	.PARAMETER DomainJoinOUPath
		The OU where the computer object for this server should be created on domain join.

	.PARAMETER FormatDrives
		If specified, any RAW, unformatted disks will be formatted as NTFS volumes.

	.EXAMPLE
		Import-Module AWSPowerShell
		.\Invoke-AWSCommonSetup.ps1 -SendToCloudWatchLogs -InstallCfnInit -InstallWMF5 -CloudWatchSSMDocument "SSM-CloudWatchLogs-ActiveDirectory" -FormatDrives -OutputBucketName "logs"

		This installs CfnInit, WMF5, enables CloudWatchLogs through the SSM document association, formats any raw, offline disks, streams the script logs to CloudWatch Logs and uploads
		the log file at the end to the "logs" bucket.

	.INPUTS
		None

	.OUTPUTS
		System.Boolean

		The output indicates whether or not the server requires a reboot to complete the configuration.

	.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 7/20/2018
#>

Param(
    [Parameter()]
    [ValidateNotNull()]
    [ValidateLength(0, 15)]
    [System.String]$NewComputerName = [System.String]::Empty,

    [Parameter()]
    [ValidateNotNull()]
    [System.String]$BucketName,

	[Parameter()]
    [ValidateNotNull()]
    [System.String]$OutputBucketName,

	[Parameter()]
	[Switch]$SendToCloudWatchLogs,

    [Parameter()]
    [ValidateNotNull()]
    [System.String]$CloudWatchConfig = [System.String]::Empty,

    [Parameter()]
    [ValidateNotNull()]
    [System.String]$CloudWatchSSMDocument = [System.String]::Empty,

    [Parameter()]
    [switch]$InstallWMF5,

    [Parameter()]
    [switch]$InstallCfnInit,
  
    [Parameter()]
    [ValidateNotNull()]
    [System.String]$DomainName,

    [Parameter()]
    [ValidateNotNull()]
    [System.String]$DomainJoinUsername,

    [Parameter()]
    [ValidateNotNull()]
    [System.Security.SecureString]$DomainJoinPassword,

    [Parameter()]
    [System.String[]]$DNSServers = @(),

    [Parameter()]
    [ValidateNotNull()]
    [System.String]$DomainJoinOUPath = [System.String]::Empty,

    [Parameter()]
    [Switch]$FormatDrives,

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

Begin {
    Import-Module -Name AWSPowerShell -ErrorAction Stop

	#region Internal Functions

    Function Write-Log {
        <#
            .SYNOPSIS
                Writes to a log file and echoes the message to the console.

            .DESCRIPTION
                The cmdlet writes text or a PowerShell ErrorRecord to a log file and displays the log message to the console at the specified logging level.

            .PARAMETER Message
                The message to write to the log file.

            .PARAMETER ErrorRecord
                Optionally specify a PowerShell ErrorRecord object to include with the message.

            .PARAMETER Level
                The level of the log message, this is either INFO, WARNING, ERROR, DEBUG, or VERBOSE. This defaults to INFO.

            .PARAMETER Path
                The path to the log file. If this is not specified, the message is only echoed out.

            .PARAMETER NoInfo
                Specify to not add the timestamp and log level to the message being written.

            .INPUTS
                System.String

                    The log message can be piped to Write-Log

            .OUTPUTS
                None

            .EXAMPLE
                try {
                    $Err = 10 / 0
                }
                catch [Exception]
                {
                    Write-Log -Message $_.Exception.Message -ErrorRecord $_ -Level ERROR
                }

                Writes an ERROR log about dividing by 0 to the default log path.

            .EXAMPLE
                Write-Log -Message "The script is starting"

                Writes an INFO log to the default log path.

            .NOTES
                AUTHOR: Michael Haken
                LAST UPDATE: 8/24/2016
        #>
        [CmdletBinding()]
        Param(
            [Parameter(Position = 2)]
            [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "VERBOSE")]
            [System.String]$Level = "INFO",

            [Parameter(Mandatory=$true, Position = 0, ValueFromPipeline = $true)]
            [System.String]$Message,

            [Parameter(Position = 1)]
            [System.Management.Automation.ErrorRecord]$ErrorRecord,

            [Parameter()]
            [System.String]$Path = $script:LogPath,

            [Parameter()]
            [switch]$NoInfo
        )

        Begin {     
        }

        Process {
            if ($ErrorRecord -ne $null) {
                $Message += "`r`n"
                $Message += ("Exception: `n" + ($ErrorRecord.Exception | Select-Object -Property * | Format-List | Out-String) + "`n")
                $Message += ("Category: " + ($ErrorRecord.CategoryInfo.Category.ToString()) + "`n")
                $Message += ("Stack Trace: `n" + ($ErrorRecord.ScriptStackTrace | Format-List | Out-String) + "`n")
                $Message += ("Invocation Info: `n" + ($ErrorRecord.InvocationInfo | Format-List | Out-String))
            }
        
            if ($NoInfo) {
                $Content = $Message
            }
            else {
                $Content = "$(Get-Date) : [$Level] $Message"
            }

            if ([System.String]::IsNullOrEmpty($Path))
            {
                $Path = [System.Environment]::GetEnvironmentVariable("LogPath", [System.EnvironmentVariableTarget]::Machine)
            }

            if (-not [System.String]::IsNullOrEmpty($Path)) 
            {
                try
                {
                    Add-Content -Path $Path -Value $Content
                }
                catch [Exception]
                {
                    Write-Warning -Message "Could not write to log file : $($_.Exception.Message)`n$Content"
                }
            }

            switch ($Level) {
                "INFO" {
                    Write-Host $Content
                    break
                }
                "WARNING" {
                    Write-Warning -Message $Content
                    break
                }
                "ERROR" {
                    Write-Error -Message $Content
                    break
                }
                "DEBUG" {
                    Write-Debug -Message $Content
                    break
                }
                "VERBOSE" {
                    Write-Verbose -Message $Content
                    break
                }
                default {
                    Write-Warning -Message "Could not determine log level to write."
                    Write-Host $Content
                    break
                }
            }

			if ($SendToCloudWatchLogs -and $script:CWLClient -ne $null) {				
				[Amazon.CloudWatchLogs.Model.InputLogEvent]$Event = New-Object -TypeName Amazon.CloudWatchLogs.Model.InputLogEvent
				$Event.Message = $Content
				$Event.Timestamp = Get-Date
				$Events = New-Object -TypeName System.Collections.Generic.List[Amazon.CloudWatchLogs.Model.InputLogEvent]
				$Events.Add($Event)
				[Amazon.CloudWatchLogs.Model.PutLogEventsRequest]$LogRequest = New-Object -TypeName Amazon.CloudWatchLogs.Model.PutLogEventsRequest($script:LogGroupName, $script:LogStreamName, $Events)
				
				if ($script:SequenceToken -ne $null -and -not [System.String]::IsNullOrEmpty($script:SequenceToken))
				{
					$LogRequest.SequenceToken = $script:SequenceToken
				}
								
				[Amazon.CloudWatchLogs.Model.PutLogEventsResponse]$Response = $script:CWLClient.PutLogEvents($LogRequest)
				$script:SequenceToken = $Response.NextSequenceToken
			}
        }

        End {
        }
    }

	Function New-AWSSplat {
		<#
			.SYNOPSIS
				Builds a hashtable that can be used as a splat for default AWS parameters.

			.DESCRIPTION
				Creates a hashtable that contains the common AWS Parameters for authentication and location. This collection can then be used as a splat against AWS PowerShell cmdlets.

			.PARAMETER Region
				The system name of the AWS region in which the operation should be invoked. For example, us-east-1, eu-west-1 etc. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

			.PARAMETER AccessKey
				The AWS access key for the user account. This can be a temporary access key if the corresponding session token is supplied to the -SessionToken parameter.

			.PARAMETER SecretKey
				The AWS secret key for the user account. This can be a temporary secret key if the corresponding session token is supplied to the -SessionToken parameter.

			.PARAMETER SessionToken
				The session token if the access and secret keys are temporary session-based credentials.

			.PARAMETER Credential
				An AWSCredentials object instance containing access and secret key information, and optionally a token for session-based credentials.

			.PARAMETER ProfileLocation 
				Used to specify the name and location of the ini-format credential file (shared with the AWS CLI and other AWS SDKs)
			
				If this optional parameter is omitted this cmdlet will search the encrypted credential file used by the AWS SDK for .NET and AWS Toolkit for Visual Studio first. If the profile is not found then the cmdlet will search in the ini-format credential file at the default location: (user's home directory)\.aws\credentials. Note that the encrypted credential file is not supported on all platforms. It will be skipped when searching for profiles on Windows Nano Server, Mac, and Linux platforms.
			
				If this parameter is specified then this cmdlet will only search the ini-format credential file at the location given.
			
				As the current folder can vary in a shell or during script execution it is advised that you use specify a fully qualified path instead of a relative path.

			.PARAMETER ProfileName
				The user-defined name of an AWS credentials or SAML-based role profile containing credential information. The profile is expected to be found in the secure credential file shared with the AWS SDK for .NET and AWS Toolkit for Visual Studio. You can also specify the name of a profile stored in the .ini-format credential file used with the AWS CLI and other AWS SDKs.

			.PARAMETER DefaultRegion
				The default region to use if one hasn't been set and can be retrieved through Get-AWSDefaultRegion. This defaults to us-east-1.

			.EXAMPLE
				New-AWSSplat -Region ([Amazon.RegionEndpoint]::USEast1) -ProfileName myprodaccount
				Creates a splat for us-east-1 using credentials stored in the myprodaccount profile.

			.INPUTS
				None

			.OUTPUTS
				System.Collections.Hashtable

			.NOTES
				AUTHOR: Michael Haken
				LAST UPDATE: 4/15/2017
		#>
		[CmdletBinding()]
		Param(
			[Parameter()]
			[Amazon.RegionEndpoint]$Region,

			[Parameter()]
			[ValidateNotNull()]
			[System.String]$ProfileName,

			[Parameter()]
			[ValidateNotNull()]
			[System.String]$AccessKey,

			[Parameter()]
			[ValidateNotNull()]
			[System.String]$SecretKey,

			[Parameter()]
			[ValidateNotNull()]
			[System.String]$SessionToken,

			[Parameter()]
			[Amazon.Runtime.AWSCredentials]$Credential,

			[Parameter()]
			[ValidateNotNull()]
			[System.String]$ProfileLocation,

			[Parameter()]
			[ValidateNotNullOrEmpty()]
			[System.String]$DefaultRegion = "us-east-1"
		)

		Begin {
		}

		Process {
			#Map the common AWS parameters
			$CommonSplat = @{}

			if ($PSBoundParameters.ContainsKey("Region") -and $Region -ne $null)
			{
				$CommonSplat.Region = $Region.SystemName
			}
			else
			{
				[System.String]$RegionTemp = Get-DefaultAWSRegion | Select-Object -ExpandProperty Region

				if (-not [System.String]::IsNullOrEmpty($RegionTemp))
				{
					#Get-DefaultAWSRegions returns a Amazon.Powershell.Common.AWSRegion object
 					$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($RegionTemp) | Select-Object -ExpandProperty SystemName
				}
				else
				{
					#No default region set
					$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($DefaultRegion) | Select-Object -ExpandProperty SystemName
				}
			}

			if ($PSBoundParameters.ContainsKey("SecretKey") -and -not [System.String]::IsNullOrEmpty($SecretKey))
			{
				$CommonSplat.SecretKey = $SecretKey
			}

			if ($PSBoundParameters.ContainsKey("AccessKey") -and -not [System.String]::IsNullOrEmpty($AccessKey))
			{
				$CommonSplat.AccessKey = $AccessKey
			}

			if ($PSBoundParameters.ContainsKey("SessionToken") -and -not [System.String]::IsNullOrEmpty($SessionToken))
			{
				$CommonSplat.SessionToken = $SessionToken
			}

			if ($PSBoundParameters.ContainsKey("ProfileName") -and -not [System.String]::IsNullOrEmpty($ProfileName))
			{
				$CommonSplat.ProfileName = $ProfileName
			}

			if ($PSBoundParameters.ContainsKey("ProfileLocation") -and -not [System.String]::IsNullOrEmpty($ProfileLocation))
			{
				$CommonSplat.ProfileLocation = $ProfileLocation
			}

			if ($PSBoundParameters.ContainsKey("Credential") -and $Credential -ne $null)
			{
				$CommonSplat.Credential = $Credential
			}

			Write-Output -InputObject $CommonSplat
		}

		End {
		}
	}

	Function New-AWSUtilitiesSplat {
		<#
			.SYNOPSIS
				Builds a hashtable that can be used as a splat for default AWS parameters.

			.DESCRIPTION
				Creates a hashtable that contains the common AWS Parameters for authentication and location. This collection can then be used as a splat against AWS Utilities PowerShell cmdlets.
				The major difference is that AWS PowerShell cmdlets take a string for the region parameter, and these cmdlets use the Amazon.RegionEndpoint object for the region parameter.

			.PARAMETER Region
				The system name of the AWS region in which the operation should be invoked. For example, us-east-1, eu-west-1 etc. This defaults to the default regions set in PowerShell, or us-east-1 if not default has been set.

			.PARAMETER AccessKey
				The AWS access key for the user account. This can be a temporary access key if the corresponding session token is supplied to the -SessionToken parameter.

			.PARAMETER SecretKey
				The AWS secret key for the user account. This can be a temporary secret key if the corresponding session token is supplied to the -SessionToken parameter.

			.PARAMETER SessionToken
				The session token if the access and secret keys are temporary session-based credentials.

			.PARAMETER Credential
				An AWSCredentials object instance containing access and secret key information, and optionally a token for session-based credentials.

			.PARAMETER ProfileLocation 
				Used to specify the name and location of the ini-format credential file (shared with the AWS CLI and other AWS SDKs)
			
				If this optional parameter is omitted this cmdlet will search the encrypted credential file used by the AWS SDK for .NET and AWS Toolkit for Visual Studio first. If the profile is not found then the cmdlet will search in the ini-format credential file at the default location: (user's home directory)\.aws\credentials. Note that the encrypted credential file is not supported on all platforms. It will be skipped when searching for profiles on Windows Nano Server, Mac, and Linux platforms.
			
				If this parameter is specified then this cmdlet will only search the ini-format credential file at the location given.
			
				As the current folder can vary in a shell or during script execution it is advised that you use specify a fully qualified path instead of a relative path.

			.PARAMETER ProfileName
				The user-defined name of an AWS credentials or SAML-based role profile containing credential information. The profile is expected to be found in the secure credential file shared with the AWS SDK for .NET and AWS Toolkit for Visual Studio. You can also specify the name of a profile stored in the .ini-format credential file used with the AWS CLI and other AWS SDKs.

			.PARAMETER DefaultRegion
				The default region to use if one hasn't been set and can be retrieved through Get-AWSDefaultRegion. This defaults to us-east-1.

			.PARAMETER AWSSplat
				An AWS Splat hashtable that will be converted into this kind of splat hashtable

			.EXAMPLE
				New-AWSUtilitiesSplat -Region ([Amazon.RegionEndpoint]::USEast1) -ProfileName myprodaccount
				Creates a splat for us-east-1 using credentials stored in the myprodaccount profile.

			.INPUTS
				None

			.OUTPUTS
				System.Collections.Hashtable

			.NOTES
				AUTHOR: Michael Haken
				LAST UPDATE: 4/15/2107
		#>
		[CmdletBinding(DefaultParameterSetName="Specify")]
		Param(
			[Parameter(ParameterSetName="Specify")]
			[ValidateNotNull()]
			[Amazon.RegionEndpoint]$Region,

			[Parameter(ParameterSetName="Specify")]
			[ValidateNotNull()]
			[System.String]$ProfileName,

			[Parameter(ParameterSetName="Specify")]
			[ValidateNotNull()]
			[System.String]$AccessKey,

			[Parameter(ParameterSetName="Specify")]
			[ValidateNotNull()]
			[System.String]$SecretKey,

			[Parameter(ParameterSetName="Specify")]
			[ValidateNotNull()]
			[System.String]$SessionToken,

			[Parameter(ParameterSetName="Specify")]
			[ValidateNotNull()]
			[Amazon.Runtime.AWSCredentials]$Credential,

			[Parameter(ParameterSetName="Specify")]
			[ValidateNotNull()]
			[System.String]$ProfileLocation,

			[Parameter()]
			[ValidateNotNullOrEmpty()]
			[System.String]$DefaultRegion = "us-east-1",

			[Parameter(ParameterSetName = "Splat")]
			[ValidateNotNull()]
			[System.Collections.Hashtable]$AWSSplat
		)

		Begin {
		}

		Process {
			#Map the common AWS parameters
			[System.Collections.Hashtable]$CommonSplat = @{}

			if ($PSCmdlet.ParameterSetName -eq "Specify")
			{
				if ($PSBoundParameters.ContainsKey("Region") -or $Region -ne $null)
				{
					[Amazon.RegionEndpoint]$CommonSplat.Region = $Region
				}
				else
				{
					[System.String]$RegionTemp = Get-DefaultAWSRegion | Select-Object -ExpandProperty Region

					if (-not [System.String]::IsNullOrEmpty($RegionTemp))
					{
						#Get-DefaultAWSRegions returns a Amazon.Powershell.Common.AWSRegion object
 						[Amazon.RegionEndpoint]$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($RegionTemp)
					}
					else
					{
						#No default region set
						[Amazon.RegionEndpoint]$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($DefaultRegion)
					}
				}

				if ($PSBoundParameters.ContainsKey("SecretKey") -and -not [System.String]::IsNullOrEmpty($SecretKey))
				{
					$CommonSplat.SecretKey = $SecretKey
				}

				if ($PSBoundParameters.ContainsKey("AccessKey") -and -not [System.String]::IsNullOrEmpty($AccessKey))
				{
					$CommonSplat.AccessKey = $AccessKey
				}

				if ($PSBoundParameters.ContainsKey("SessionToken") -and -not [System.String]::IsNullOrEmpty($SessionToken))
				{
					$CommonSplat.SessionToken = $SessionToken
				}

				if ($PSBoundParameters.ContainsKey("ProfileName") -and -not [System.String]::IsNullOrEmpty($ProfileName))
				{
					$CommonSplat.ProfileName = $ProfileName
				}

				if ($PSBoundParameters.ContainsKey("ProfileLocation") -and -not [System.String]::IsNullOrEmpty($ProfileLocation))
				{
					$CommonSplat.ProfileLocation = $ProfileLocation
				}

				if ($PSBoundParameters.ContainsKey("Credential") -and $Credential -ne $null)
				{
					$CommonSplat.Credential = $Credential
				}
			}
			else
			{
				foreach ($Key in $AWSSplat.GetEnumerator())
				{
					if ($Key.Name -eq "Region" -and -not [System.String]::IsNullOrEmpty($Key.Value))
					{
						$CommonSplat.Region = [Amazon.RegionEndpoint]::GetBySystemName($Key.Value)
					}
					else
					{
						if ($Key.Value -ne $null)
						{
							Write-Verbose -Message "Adding key $($Key.Name) $($Key.Value)"
							$CommonSplat."$($Key.Name)" = $Key.Value
						}
					}
				}
			}

			Write-Output -InputObject $CommonSplat
		}

		End {
		}
	}

    Function Get-AWSSoftware {
		<#
			.SYNOPSIS
				Retrieves a list of Amazon installed software.

			.DESCRIPTION
				Retrieves a list of Amazon installed software.
			
			.EXAMPLE
				Get-AWSSoftware

			.INPUTS
				None

			.OUTPUTS
				PSCustomObject

			.NOTES
				AUTHOR: Michael Haken
				LAST UPDATE: 4/15/2017
		#>
        Param()

        Begin {
        }

        Process {
            Write-Output -InputObject (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | `
                Where-Object -FilterScript {$_.GetValue("Publisher") -like "Amazon*" -or $_.GetValue("Publisher") -like "AWS*" } | `
                Select-Object -Property @{Name = "Temp"; Expression = { $Path = $_.Name.Replace("HKEY_LOCAL_MACHINE", "HKLM:"); 
                    $Results = @{}; 
                    $_.Property | ForEach-Object { 
                        $Results[$_] = Get-ItemProperty -Path $Path -Name $_ | Select-Object -ExpandProperty $_; 
                    };  
                    $Results.Id = $_.Name
                    Write-Output -InputObject $Results 
                }
            } | Select-Object -ExpandProperty Temp)
        }
        
        End {
        }
    }

    Function Set-DNSServers {
		<#
			.SYNOPSIS
				Sets DNS servers for the client.

			.DESCRIPTION
				Sets DNS servers for the client on every network interface.

			.PARAMETER DNSServers
				The set of DNS servers that will be applied to each network interface
			
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
        Param(
            [Parameter(Mandatory=$true, ValueFromPipeline = $true)]
			[ValidateNotNull()]
            [System.String[]]$DNSServers
        )

        Begin {
        }

        Process {
            Get-NetAdapter | Select-Object -Property Name,ifIndex | ForEach-Object {
                try {
                    Write-Log -Message "Setting DNS servers to $DNSServers on interface $($_.Name)."
                    Set-DnsClientServerAddress -ServerAddresses $DNSServers -InterfaceIndex $_.ifIndex
                    Write-Log -Message "Successfully set DNS servers."
                }
                catch [Exception] {
                    Write-Log -Message "Failed to set DNS servers on interface $($_.Name)." -ErrorRecord $_ -Level ERROR
                }
            }
        }

        End {
        }
    }

    Function Enable-CloudWatchLogs {
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

        Begin {
        }

        Process {
			[System.Collections.Hashtable]$AWSSplat = New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation 

    		if ($AWSSplat.Region -ne $script:CalculatedRegion)
    		{
        		$AWSSplat.Region = $script:CalculatedRegion
    		}

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
                        New-SSMAssociation -InstanceId $InstanceId -Name "AWS-UpdateSSMAgent" -Force @AWSSplat | Out-Null
                    }
                    catch [Amazon.SimpleSystemsManagement.Model.AssociationAlreadyExistsException]
                    {
                        Write-Log -Message "The AWS-UpdateSSMAgent association already exists."
                    }

                    try
                    {
                        Write-Log -Message "Associating CloudWatch SSM Document $SSMDocument."
                        New-SSMAssociation -Target  @{Key="instanceids"; Values=@($InstanceId)} -Name $SSMDocument -Parameter @{"status" = "Enabled"} -Force @AWSSplat | Out-Null
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
            
                        Copy-S3Object -BucketName $Bucket -Key $Key -LocalFile $CloudWatchLogConfigDestination -Force @AWSSplat
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
        }

        End {
        }
    }

    Function Get-EC2InstanceRegion {
    	<#
        	.SYNOPSIS
            	Gets the current region of the EC2 instance from instance metadata.

        	.DESCRIPTION
            	The cmdlet uses the EC2 instance metadata of the local or remote computer to get the AWS Region it is running in.

        	.PARAMETER ComputerName
            	The computer to the get the region for, this defaults to the local machine. The computer must be an AWS EC2 instance.

        	.PARAMETER Credential
            	The credentials used to connect to a remote computer.

			.EXAMPLE
            	$Region = Get-EC2InstanceRegion

            	Gets the AWS Region of the current machine.

        	.INPUTS
            	System.String

        	.OUTPUTS
            	System.String

        	.NOTES
            	AUTHOR: Michael Haken
            	LAST UPDATE: 5/3/2017
    	#>
    	[CmdletBinding()]
    	Param(
        	[Parameter(ValueFromPipeline = $true)]
        	[ValidateNotNullOrEmpty()]
        	$ComputerName,

        	[Parameter()]
        	[ValidateNotNull()]
        	[System.Management.Automation.Credential()]
        	[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    	)

    	Begin {
    	}

    	Process {       
        	if ($PSBoundParameters.ContainsKey("ComputerName") -and $ComputerName -inotin @(".", "localhost", "", $env:COMPUTERNAME, "127.0.0.1"))
        	{
            	[System.String]$Region = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                	[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
                	Write-Output -InputObject (ConvertFrom-Json -InputObject ($WebClient.DownloadString("http://169.254.169.254/latest/dynamic/instance-identity/document"))).Region
            	} -Credential $Credential
        	}
        	else
        	{
            	[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
            	[System.String]$Region = (ConvertFrom-Json -InputObject ($WebClient.DownloadString("http://169.254.169.254/latest/dynamic/instance-identity/document"))).Region
        	}

        	Write-Output -InputObject $Region
    	}

    	End {
    	}
	}

    Function Get-EC2InstanceId {
    	<#
        	.SYNOPSIS
            	Gets the current instance id of the EC2 instance from instance metadata.

        	.DESCRIPTION
            	The cmdlet uses the EC2 instance metadata of the local or remote computer to get the instance's id.

        	.PARAMETER ComputerName
            	The computer to the get the id for, this defaults to the local machine. The computer must be an AWS EC2 instance.

        	.PARAMETER Credential
            	The credentials used to connect to a remote computer.

			.EXAMPLE
            	$Id = Get-EC2InstanceId

            	Gets the instance id of the current machine.

        	.INPUTS
            	System.String

        	.OUTPUTS
            	System.String

        	.NOTES
            	AUTHOR: Michael Haken
            	LAST UPDATE: 5/3/2017
    	#>
    	[CmdletBinding()]
    	Param(
        	[Parameter(ValueFromPipeline = $true)]
        	[ValidateNotNullOrEmpty()]
        	[System.String]$ComputerName,

        	[Parameter()]
        	[ValidateNotNull()]
        	[System.Management.Automation.Credential()]
        	[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    	)

    	Begin {
    	}

    	Process {       
        	if ($PSBoundParameters.ContainsKey("ComputerName") -and $ComputerName -inotin @(".", "localhost", "", $env:COMPUTERNAME, "127.0.0.1"))
        	{
            	[System.String]$Id = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                	[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
                	Write-Output -InputObject $WebClient.DownloadString("http://169.254.169.254/latest/meta-data/instance-id")
            	} -Credential $Credential
        	}
        	else
        	{
            	[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
            	[System.String]$Id = $WebClient.DownloadString("http://169.254.169.254/latest/meta-data/instance-id")
        	}

        	Write-Output -InputObject $Id
    	}

    	End {
    	}
	}

	Function Install-WMF5 {
		Param()

		Begin {
		}

		Process {
			if ($PSVersionTable.PSVersion.Major -lt 5) 
			{
				Write-Log -Message "WMF 5 is not installed, installing now."

				switch ($MajorOSVersion) {
					$WS2016_MAJOR {
						$Url = [System.String]::Empty
						$PackageId = [System.String]::Empty
						break
					}
					$WS2012R2_MAJOR {
						$Url = "https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/Win8.1AndW2K12R2-KB3134758-x64.msu"
						$PackageId = "KB3134758"
						break
					}
					$WS2012_MAJOR {
						$Url = "https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/W2K12-KB3134759-x64.msu"
						$PackageId = "KB3134759"
						break
					}
					$WS2008R2_MAJOR {
						$Url = "https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/Win7AndW2K8R2-KB3134760-x64.msu"
						$PackageId = "KB3134760"
						break
					}
					default {
						Write-Log -Message "Cannot match current Major OS Version for WMF installation." -Level ERROR
						$Url = [System.String]::Empty
						break
					}
				}

				if (![System.String]::IsNullOrEmpty($Url)) 
				{				
					[System.Uri]$Uri = New-Object -TypeName System.Uri($Url)
					$FileName = $Uri.Segments[$Uri.Segments.Count - 1]
					$Destination = "$env:TEMP\$FileName"

					$WebClient = New-Object -TypeName System.Net.WebClient
					$WebClient.DownloadFile($Url, $Destination)
					
					try {
						[System.Diagnostics.Process]$Process = New-Object -TypeName System.Diagnostics.Process
						$Process.StartInfo.RedirectStandardOutput = $true
						$Process.StartInfo.UseShellExecute = $false
						$Process.StartInfo.CreateNoWindow = $true
						$Process.StartInfo.RedirectStandardError = $true
						$Process.StartInfo.Filename = "$env:SystemRoot\System32\WUSA.EXE"
						$Process.StartInfo.Arguments = (@($Destination, "/install", "/quiet", "/norestart") -join " ")
						$Process.Start()
						$Process.WaitForExit()
					}
					finally {
						Remove-Item -Path $Destination -Force
					}
				}
			}
			else 
			{
					Write-Log -Message "PowerShell version $($PSVersionTable.PSVersion.Major) detected, WMF5 already installed."
			}
		}

		End {
		}
	}

	#endregion

	#region Constants

    $script:CfnInitSource = "https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.msi"
    $script:CfnInitDestination = "$env:SystemDrive\aws-cfn-bootstrap-latest.msi"
    $script:WMF5Destination = "$env:SystemDrive\wmf5.msu"
    $script:LogPath = "$env:SystemDrive\AWSBootstrap.log"
	$script:InstanceId = Get-EC2InstanceId
	$script:LogGroupName = "/aws/ec2/$script:InstanceId"
	$script:LogStreamName = "invoke-awscommonsetup.ps1"

	# This is done to make sure the user didn't specify a different region than the one
	# the instance is in
    $script:CalculatedRegion = Get-EC2InstanceRegion

	Set-Variable -Scope "script" -Name "AWSSplat" -Value (New-AWSSplat -Region $Region -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Credential $Credential -ProfileLocation $ProfileLocation)

	if ($script:AWSSplat.Region -ne $script:CalculatedRegion)
    {
        $script:AWSSplat.Region = $script:CalculatedRegion
    }	

	$script:MajorOSVersion = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property @{Name = "Major"; Expression = {$_.Version.Split(".")[0] + "." +$_.Version.Split(".")[1]}} | Select-Object -ExpandProperty Major
	$script:MinorOSVersion = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property @{Name = "Minor"; Expression = {$_.Version.Split(".")[2]}} | Select-Object -ExpandProperty Minor

	# Supported Operating Systems
	$WS2008R2_MAJOR                 = "6.1"
	$WS2012_MAJOR                   = "6.2"
	$WS2012R2_MAJOR                 = "6.3"
	$WS2016_MAJOR                   = "10.0"

	#endregion

	#region CloudWatch Logs Setup

	if ($SendToCloudWatchLogs)
	{
		$Group =  Get-CWLLogGroups -LogGroupNamePrefix $script:LogGroupName #@script:AWSSplat

		if ($Group -eq $null)
		{
			New-CWLLogGroup -LogGroupName $script:LogGroupName -Force #@script:AWSSplat
		}

		$Stream = Get-CWLLogStreams -LogGroupName $script:LogGroupName -LogStreamNamePrefix $script:LogStreamName #@script:AWSSplat

		if ($Stream -eq $null) 
		{
			New-CWLLogStream -LogGroupName $script:LogGroupName -LogStreamName $script:LogStreamName -Force #@script:AWSSplat
		}

		$ArgList = @()

		if ($script:AWSSplat.ContainsKey("SecretKey") -and $script:AWSSplat.ContainsKey("AccessKey")) {
			$ArgList += $script:AWSSplat["AccessKey"]
			$ArgList += $script:AWSSplat["SecretKey"]

			if ($script:AWSSplat.ContainsKey("SessionToken")) {
				$ArgList += $script:AWSSplat["SessionToken"]
			}

			if ($script:AWSSplat.ContainsKey("Region")) {
				$ArgList += $script:AWSSplat["Region"]
			}
		}
		elseif ($script:AWSSplat.ContainsKey("Credential")) {
			$ArgList += $Credential

			if ($script:AWSSplat.ContainsKey("Region")) {
				$ArgList += $script:AWSSplat["Region"]
			}
		}

		[Amazon.CloudWatchLogs.IAmazonCloudWatchLogs]$script:CWLClient = New-Object -TypeName Amazon.CloudWatchLogs.AmazonCloudWatchLogsClient -ArgumentList $ArgList
		[Amazon.CloudWatchLogs.Model.DescribeLogStreamsRequest]$script:StreamsRequest = New-Object -TypeName Amazon.CloudWatchLogs.Model.DescribeLogStreamsRequest($script:LogGroupName)
		$script:StreamsRequest.LogStreamNamePrefix = $script:LogStreamName
		[System.String]$script:SequenceToken = $script:CWLClient.DescribeLogStreams($script:StreamsRequest) | Select-Object -ExpandProperty LogStreams | Select-Object -First 1 | Select-Object -ExpandProperty UploadSequenceToken
	}

	#endregion

	#region Initial Config Setup

	Write-Log -Message "Determined region is $script:CalculatedRegion." -Level DEBUG
    Write-Log -Message "Setting execution policy to unrestricted." -Level DEBUG
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

    Write-Log -Message "Enabling task scheduler history." -Level DEBUG
    $LogName = 'Microsoft-Windows-TaskScheduler/Operational'
    $EventLog = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogConfiguration($LogName)
    $EventLog.IsEnabled = $true
    $EventLog.SaveChanges()
	
	#endregion
}

Process 
{    
    [System.Boolean]$RebootRequired = $false
    
    try
    {      
        #region Cfn Bootstrap
        
        if ($InstallCfnInit) 
        {
            try 
            {
				[System.Net.WebClient]$WebClient = New-Object -TypeName System.Net.WebClient
                Write-Log -Message "Downloading CfnInit files."
                $WebClient.DownloadFile($script:CfnInitSource, $script:CfnInitDestination)
                Start-Process -FilePath $script:CfnInitDestination -ArgumentList @("/qn") -Wait | Out-Null
                Remove-Item -Path $script:CfnInitDestination -Force | Out-Null
                Write-Log -Message "Finished CfnInit Installation."
            }
            catch [Exception]
            {
                Write-Log -Message "Failed during CfnInit Installation." -ErrorRecord $_ -Level ERROR
            }
        }

        #endregion

        #region WMF5

        if ($InstallWMF5) 
        {
			try 
			{
            	Write-Log -Message "Downloading and Installing WMF5 files."          
            	Install-WMF5
            	Write-Log -Message "Finished WMF5 Installation."
            	$RebootRequired = $true
			}
			catch [Exception]
			{
				Write-Log -Message "Failed during WMF5 installation." -ErrorRecord $_ -Level ERROR
			}
        }

		#endregion

		#region DNS

		# Do this after CfnInit and WMF5 in case the instance can't resolve public
		# DNS with these DNS servers

        if ($DNSServers -ne $null -and $DNSServers.Length -gt 0)
        {
			try 
			{
            	Set-DNSServers -DNSServers $DNSServers
			}
			catch [Exception]
			{
				Write-Log -Message "Failed during setting DNS servers." -ErrorRecord $_ -Level ERROR
			}
        }

        #endregion

        #region Domain Join

		if (-not [System.String]::IsNullOrEmpty($DomainName) -and 
            -not [System.String]::IsNullOrEmpty($DomainJoinUsername) -and 
            -not [System.String]::IsNullOrEmpty($DomainJoinPassword) -and 
            ($DNSServers -eq $null -or 
            $DNSServers.Length -eq 0)
        )
		{
			Write-Log -Message "Domain join information was specified, but DNS server information was not. Domain join could not be processed." -Level ERROR
		}

        if (-not [System.String]::IsNullOrEmpty($DomainName) -and 
            -not [System.String]::IsNullOrEmpty($DomainJoinUsername) -and 
            -not [System.String]::IsNullOrEmpty($DomainJoinPassword) -and 
            $DNSServers -ne $null -and 
            $DNSServers.Length -gt 0
        )
        {
			try 
			{
            	$Comp = Get-CimInstance -Class Win32_ComputerSystem

            	if ($Comp.PartOfDomain -eq $true -and $Comp.Domain -eq $DomainName) 
            	{
                	Write-Log -Message "The computer is already part of the destination domain." -Level WARNING
            	}
            	else 
            	{
                	Write-Log -Message "Joining domain $DomainName in path $DomainJoinOUPath."

                	try
                	{
                    	[System.Collections.Hashtable]$DomainJoinSplat = @{}

                    	if (-not [System.String]::IsNullOrEmpty($DomainJoinOUPath) -and $DomainJoinOUPath.ToLower() -ine "computers")
                    	{
                        	$DomainJoinSplat.OUPath = $DomainJoinOUPath
                    	}

						# If a new computer name was specified, this will update it during domain join
                    	if (-not [System.String]::IsNullOrEmpty($NewComputerName))
                    	{
                        	$DomainJoinSplat.NewName = $NewComputerName
                    	}

                    	$ShortDomain = $DomainName.Split(".")[0]

                    	$UserName = ""

                    	# Domain\Username format
                    	if ($DomainJoinUsername.Contains("\")) 
                    	{
                        	$UserName = $DomainJoinUsername
                    	}
                    	# UPN format
                    	elseif ($DomainJoinUsername.Contains("@")) 
                    	{
                        	$Parts = $DomainJoinUsername.Split("@")
                        	$UserName = "$ShortDomain\$($Parts[0])"
                    	}
                    	# Just a user name
                    	else 
                    	{
                        	$UserName = "$ShortDomain\$DomainJoinUsername"
                    	}

                    	Add-Computer -DomainName $DomainName `
                        	-Credential (New-Object System.Management.Automation.PSCredential($UserName, $DomainJoinPassword)) `
                        	-Force `
                        	-ErrorAction Stop `
                        	@DomainJoinSplat
                    
                    	$RebootRequired = $true
                    	Write-Log -Message "Successfully joined domain."
                	}
                	catch [Exception]
                	{
                    	Write-Log -Message "Problem joining the $DomainName domain." -ErrorRecord $_ -Level ERROR
                	}
            	}
			}
			catch [Exception]
			{
				Write-Log -Message "Failed during domain join phase." -ErrorRecord $_ -Level ERROR
			}
        }
        elseif (-not [System.String]::IsNullOrEmpty($NewComputerName))
        {
			try 
			{
            	Rename-Computer -NewName $NewComputerName -Force -Confirm:$false
            	$RebootRequired = $true
			}
			catch [Exception]
			{
				Write-Log -Message "Failed during computer rename." -ErrorRecord $_ -Level ERROR
			}
        }

        #endregion
        
        #region CloudWatch Logs

        if (-not [System.String]::IsNullOrEmpty($CloudWatchSSMDocument) -or
			(-not [System.String]::IsNullOrEmpty($CloudWatchConfig) -and -not [System.String]::IsNullOrEmpty($BucketName))
		)
        {
			Write-Log -Message "Enabling CloudWatch Logs"
			try 
			{
				$UtilSplat = New-AWSUtilitiesSplat -AWSSplat $script:AWSSplat

            	$CWSplat = @{}

            	if ($PSBoundParameters.ContainsKey("BucketName") -and $PSBoundParameters.ContainsKey("CloudWatchConfig"))
            	{
                	$CWSplat.Add("Bucket", $BucketName)
                	$CWSplat.Add("Key", $CloudWatchConfig)
            	}
            	elseif ($PSBoundParameters.ContainsKey("CloudWatchSSMDocument"))
            	{
                	$CWSplat.Add("SSMDocument", $CloudWatchSSMDocument)
            	}

            	Enable-CloudWatchLogs @CWSplat @UtilSplat
			}
			catch [Exception]
			{
				Write-Log -Message "Failed during CloudWatch Logs setup." -ErrorRecord $_ -Level ERROR
			}
        }

        #endregion

        #region FormatDrives

        if ($FormatDrives)
        {
            try
            {
                Write-Log -Message "Formatting all currently offline, raw disks."
                Stop-Service -Name ShellHWDetection -Force -Confirm:$false

                $NewDisks = Get-Disk | Where-Object {$_.OperationalStatus -eq "Offline" -or $_.PartitionStyle -eq "RAW"}
                $NewDisks | Set-Disk -IsOffline $false
                $NewDisks | Set-Disk -IsReadOnly $false

                $NewDisks | Where-Object {$_.PartitionStyle -eq "RAW"} | Initialize-Disk -PartitionStyle GPT -Confirm:$false -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS

                Start-Service -Name ShellHWDetection -Confirm:$false
            }
            catch [Exception]
            {
                Write-Log -Message "Failed formatting new disks." -ErrorRecord $_ -Level ERROR
            }
        }

        #endregion

		if (-not [System.String]::IsNullOrEmpty($OutputBucketName))
		{
			Write-S3Object -BucketName $OutputBucketName -File $script:LogPath -Key "$script:InstanceId`_invoke-commonsetup.ps1.txt"
		}
    }
    catch [Exception] 
	{
        Write-Log -ErrorRecord $_ -Level ERROR
    }

    Write-Output -InputObject $RebootRequired
}

End {
}
