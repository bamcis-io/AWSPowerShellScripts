[CmdletBinding(DefaultParameterSetName = "Cred")]
Param(
	[Parameter(Position = 0)]
	[ValidateNotNullOrEmpty()]
	[System.String]$DomainName = [System.String]::Empty,

	[Parameter(Position = 1)]
	[ValidateNotNullOrEmpty()]
	[System.String]$OUPath = [System.String]::Empty,

	[Parameter(Position = 2, ParameterSetName = "Cred")]
	[ValidateNotNull()]
	[System.Management.Automation.Credential()]
	[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

	[Parameter(ParameterSetName = "Pass", Mandatory = $true)]
	[Parameter(ParameterSetName = "EncryptedPass", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Username,

	[Parameter(ParameterSetName = "Pass", Mandatory = $true)]
	[ValidateNotNull()]
	[System.String]$Password,

	[Parameter(ParameterSetName = "EncryptedPass", Mandatory = $true)]
	[System.String]$KMSEncryptedPassword,

	[Parameter(Position = 3)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Server = [System.String]::Empty,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String]$NewName
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

if (-not [System.String]::IsNullOrEmpty($DomainName))
{
	if ($PSCmdlet.ParameterSetName -eq "Pass")
	{
		if (-not $Username.Contains("\"))
		{
			$Username = "$($DomainName.Split(".")[0])\$Username"
		}

		$Credential = New-Object -TypeName System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
	}
	elseif ($PSCmdlet.ParameterSetName -eq "EncryptedPass")
	{
		[System.Byte[]]$Bytes = [System.Convert]::FromBase64String($KMSEncryptedPassword)
		[System.IO.MemoryStream]$MStream = New-Object -TypeName System.IO.MemoryStream($Bytes, 0, $Bytes.Length)
		[Amazon.KeyManagementService.Model.DecryptResponse]$Response = Invoke-KMSDecrypt -CipherTextBlob $MStream
		$Password = [System.Text.Encoding]::UTF8.GetString($Response.PlainText.ToArray())

		if (-not $Username.Contains("\"))
		{
			$Username = "$($DomainName.Split(".")[0])\$Username"
		}

		$Credential = New-Object -TypeName System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
	}

	[System.Collections.Hashtable]$Splat = @{}

	if (-not [System.String]::IsNullOrEmpty($OUPath))
	{
		$Splat.Add("OUPath", $OUPath)
	}

	if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
	{
		$Splat.Add("Credential", $Credential)
	}

	if (-not [System.String]::IsNullOrEmpty($Server))
	{
		$Splat.Add("Server", $Server)
	}

	if (-not [System.String]::IsNullOrEmpty($NewName))
	{
		$Splat.Add("NewName", $NewName)
	}

	Add-Computer -DomainName $DomainName @Splat
}