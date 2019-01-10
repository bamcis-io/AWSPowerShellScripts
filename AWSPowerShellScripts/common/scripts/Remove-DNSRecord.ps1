[CmdletBinding(DefaultParameterSetName = "Cred")]
Param(
	[Parameter(Mandatory = $true, Position = 0)]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$Record,

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
	[ValidateNotNullOrEmpty()]
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

try {

	$DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain
	$DNSServer = Get-ADDomainController -ForceDiscover -Discover -DomainName $DomainName | Select-Object -First 1 -ExpandProperty HostName
	$Session = New-CimSession -ComputerName $DNSServer @Splat 

	foreach ($Item in $Record)
	{
		try
		{
			Write-Host "Retrieving records for $Item"

			[Microsoft.Management.Infrastructure.CimInstance[]]$Records = Get-DnsServerResourceRecord -Name $Item -ZoneName $DomainName -CimSession $Session -ErrorAction SilentlyContinue

			if ($Records -ne $null -and $Records.Length -gt 0)
			{
				Write-Host "Removed DNS Records:"
				$Records | Remove-DnsServerResourceRecord -ZoneName $DomainName -CimSession $Session -Force -Confirm:$false -PassThru
			}
			else
			{
				Write-Host "No DNS records for $Item to remove."
			}
		}
		catch [Exception]
		{
			Write-Warning -Message "Could not remove records for $Item`: $($_.Exception.Message)"
		}
	}

	Remove-CimSession -CimSession $Session
}
catch [Exception] 
{
	Write-Warning -Message "Error during removal process: $($_.Exception.Message).`r`n$($_.Exception.StackTrace)"
}