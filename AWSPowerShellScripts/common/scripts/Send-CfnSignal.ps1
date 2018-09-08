[CmdletBinding()]
Param(
	[Parameter()]
	[System.Boolean]$Success,

	[Parameter(ParameterSetName = "Resource")]
	[ValidateNotNullOrEmpty()]
	[System.String]$AccessKey,

	[Parameter(ParameterSetName = "Resource")]
	[ValidateNotNullOrEmpty()]
	[System.String]$SecretKey,

	[Parameter(ParameterSetName = "Resource")]
	[ValidateNotNullOrEmpty()]
	[System.String]$CredentialFile,

	[Parameter()]
	[System.Int32]$ExitCode,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String]$Id,

	[Parameter(ParameterSetName = "Resource")]
	[ValidateNotNullOrEmpty()]
	[System.String]$HttpProxy,

	[Parameter(ParameterSetName = "Resource")]
	[ValidateNotNullOrEmpty()]
	[System.String]$HttpsProxy,

	[Parameter(ParameterSetName = "Resource")]
	[ValidateNotNullOrEmpty()]
	[System.String]$Region = "us-east-1",

	[Parameter(ParameterSetName = "Resource", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Resource,

	[Parameter(ParameterSetName = "Resource")]
	[ValidateNotNullOrEmpty()]
	[System.String]$Role,

	[Parameter(ParameterSetName = "Resource", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Stack,

	[Parameter(ParameterSetName = "Resource")]
	[ValidateNotNullOrEmpty()]
	[System.Uri]$Url,

	[Parameter(ParameterSetName = "WaitCondition")]
	[ValidateNotNullOrEmpty()]
	[System.String]$Reason,
	
	[Parameter(ParameterSetName = "WaitCondition")]
	[ValidateNotNullOrEmpty()]
	[System.String]$Data = [System.String]::Empty,

	[Parameter(ParameterSetName = "WaitCondition", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$WaitConditionUrl
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$Splat = @()

if ($PSBoundParameters.ContainsKey("ExitCode"))
{
	$Splat += "--exit-code $ExitCode"
}
elseif ($PSBoundParameters.ContainsKey("Success"))
{
	$Splat += "--success $($Success.ToString())"
}

if ($PSBoundParameters.ContainsKey("Id"))
{
	$Splat += "--id `"$Id`""
}

if ($PSCmdlet.ParameterSetName -eq "Resource")
{
	$Splat += "--resource `"$Resource`""
	$Splat += "--stack `"$Stack`""

	if ($PSBoundParameters.ContainsKey("CredentialFile"))
	{
		$Splat += "--credential-file `"$CredentialFile`""
	}
	elseif($PSBoundParameters.ContainsKey("Role"))
	{
		$Splat += "--role `"$Role`""
	}
	elseif($PSBoundParameters.ContainsKey("AccessKey") -and $PSBoundParameters.ContainsKey("SecretKey"))
	{
		$Splat += "--access-key `"$AccessKey`""
		$Splat += "--secret-key `"$SecretKey`""
	}

	if ($PSBoundParameters.ContainsKey("HttpsProxy"))
	{
		$Splat += "--https-proxy `"$HttpsProxy`""
	}
	elseif($PSBoundParameters.ContainsKey("HttpProxy"))
	{
		$Splat += "--http-proxy `"$HttpProxy`""
	}

	if ($PSBoundParameters.ContainsKey("Region"))
	{
		$Splat += "--region `"$Region`""
	}

	if ($PSBoundParameters.ContainsKey("Url"))
	{
		$Splat += "--url `"$Url`""
	}
}
else 
{
	if ($PSBoundParameters.ContainsKey("Data"))
	{
		$Splat += "--data `"$Data`""
	}

	if ($PSBoundParameters.ContainsKey("Reason"))
	{
		$Splat += "--reason `"$Reason`""
	}

	$Splat += [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($WaitConditionUrl))
}

[System.Diagnostics.ProcessStartInfo]$StartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
$StartInfo.FileName = "cfn-signal.exe"
$StartInfo.Arguments = $Splat
$StartInfo.RedirectStandardOutput = $true
$StartInfo.RedirectStandardError = $true
$StartInfo.CreateNoWindow = $true
$StartInfo.LoadUserProfile = $false
$StartInfo.UseShellExecute = $false

[System.Diagnostics.Process]$Process = New-Object -TypeName System.Diagnostics.Process
$Process.StartInfo = $StartInfo
$Process.Start() | Out-Null

[System.String]$Output = $Process.StandardOutput.ReadToEnd()
[System.String]$Err = $Process.StandardError.ReadToEnd()

$Process.WaitForExit()

$LASTEXITCODE = $Process.ExitCode

if ($Process.ExitCode -eq 0)
{
    Write-Output -InputObject $Output
}
else
{
    Write-Output -InputObject $Err
}