[CmdletBinding(DefaultParameterSetName = "Cred")]
Param(
	[Parameter()]
	[ValidatePattern("^\\\\(?:[a-zA-Z0-9].?)+\\(?:(?:[-a-zA-Z0-9_.])+\\?)+\`$?$")]
	[System.String]$FileShare,

	[Parameter(ParameterSetName = "Cred", Mandatory = $true)]
	[ValidateNotNull()]
	[System.Management.Automation.Credential()]
	[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

	[Parameter(ParameterSetName = "Pass", Mandatory = $true)]
	[Parameter(ParameterSetName = "EncryptedPass", Mandatory = $true)]
	[Parameter(ParameterSetName = "SSMParameterStore", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Username,

	[Parameter(ParameterSetName = "Pass", Mandatory = $true)]
	[ValidateNotNull()]
	[System.String]$Password,

	[Parameter(ParameterSetName = "EncryptedPass", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$KMSEncryptedPassword,

	[Parameter(ParameterSetName = "SSMParameterStore", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$SSMPasswordParameterName
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

if ($PSCmdlet.ParameterSetName -ne "Cred")
{
	if (-not $Username.Contains("\"))
	{
		$DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain
		$Username = "$($DomainName.Split(".")[0])\$Username"
	}

	switch ($PSCmdlet.ParameterSetName)
	{
		"Pass" {
			# Do nothing		
			break
		}
		"EncryptedPass" {
			[System.Byte[]]$Bytes = [System.Convert]::FromBase64String($KMSEncryptedPassword)
			[System.IO.MemoryStream]$MStream = New-Object -TypeName System.IO.MemoryStream($Bytes, 0, $Bytes.Length)
			[Amazon.KeyManagementService.Model.DecryptResponse]$Response = Invoke-KMSDecrypt -CipherTextBlob $MStream
			$Password = [System.Text.Encoding]::UTF8.GetString($Response.PlainText.ToArray())

			break
		}
		"SSMParameterStore" {
			try
			{
				[Amazon.SimpleSystemsManagement.Model.GetParametersResponse]$Response =  Get-SSMParameterValue -Name $SSMPasswordParameterName -WithDecryption $true

				if ($Response -eq $null -or ($Response.InvalidParameters -ne $null -and $Response.InvalidParameters.Count -gt 0 -and $Response.InvalidParameters[0] -ieq $SSMPasswordParameterName))
				{
					throw "Could not find an SSM Parameter Store Key with a value of $SSMPasswordParameterName."
				}

				$Password = $Response.Parameters | Select-Object -First 1 -ExpandProperty Value
			}
			catch [EXception]
			{
				throw "Could not retrieve the SSM Parameter Store Key for the domain password.`r`n$($_.Exception.GetType().FullName)`r`n$($_.Exception.Message)"
			}
		
			break
		}
		default {
			throw "Unknown parameter set $($PSCmdlet.ParameterSetName)."
		}
	}

	$Credential = New-Object -TypeName System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
}

[System.Collections.Hashtable]$Splat = @{}

if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
{
	$Splat.Add("Credential", $Credential)
	$Splat.Add("ComputerName", ".")
	$Splat.Add("Authentication", "Credssp")
}

Invoke-Command -ScriptBlock {
	[System.Collections.Hashtable]$Splat = @{}

	if ([System.String]::IsNullOrEmpty($Using:FileShare))
	{
		$Splat.Add("NoWitness", $true) # Node majority
	}
	else
	{
		$Splat.Add("FileShareWitness", $Using:FileShare) # Node and file share majority
	}

	Set-ClusterQuorum @Splat

} @Splat

