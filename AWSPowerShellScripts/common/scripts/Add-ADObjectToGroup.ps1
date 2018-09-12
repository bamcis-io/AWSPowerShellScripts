[CmdletBinding(DefaultParameterSetName = "Cred")]
Param(
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$Members,

	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$Groups,

	[Parameter()]
	[Switch]$WaitForGroup,

	[Parameter()]
	[System.Int32]$Timeout = 600,

	[Parameter(Position = 2, ParameterSetName = "Cred", Mandatory = $true)]
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
	[System.String]$KMSEncryptedPassword
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

	if ($PSCmdlet.ParameterSetName -eq "EncryptedPass")
	{
		[System.Byte[]]$Bytes = [System.Convert]::FromBase64String($KMSEncryptedPassword)
		[System.IO.MemoryStream]$MStream = New-Object -TypeName System.IO.MemoryStream($Bytes, 0, $Bytes.Length)
		[Amazon.KeyManagementService.Model.DecryptResponse]$Response = Invoke-KMSDecrypt -CipherTextBlob $MStream
		$Password = [System.Text.Encoding]::UTF8.GetString($Response.PlainText.ToArray())
	}

	$Credential = New-Object -TypeName System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
}

[System.Collections.Hashtable]$Splat = @{}

if ($Credential -ne [System.Management.Automation.PSCredential]::Empty)
{
	$Splat.Add("Credential", $Credential)
}

Import-Module -Name ActiveDirectory

foreach ($Group in $Groups)
{
	if ($WaitForGroup)
	{
		$Counter = 0
		while ($Counter -lt $Timeout)
		{
			try {
				$ADGroup = Get-ADGroup -Identity $Group -ErrorAction SilentlyContinue
				break
			}
			catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
				Start-Sleep -Seconds 60
				$Counter += 60
			}
		}
	}

	Add-ADGroupMember -Members $Members -Identity $Group @Splat
}