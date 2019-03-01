[CmdletBinding(DefaultParameterSetName = "Cred")]
Param(
	[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$ClusterNameObject,

	[Parameter(Position = 1)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Path,
	
	[Parameter(Position = 2, ParameterSetName = "Cred")]
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

	Import-Module -Name ActiveDirectory

	$CNO = Get-ADComputer -Identity $Using:ClusterNameObject

	[System.Security.Principal.SecurityIdentifier]$Sid = $CNO.SID

	[System.DirectoryServices.ActiveDirectoryAccessRule]$ReadAce = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule(
		$Sid, 
		@([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty, [System.DirectoryServices.ActiveDirectoryRights]::GenericExecute),
		[System.Security.AccessControl.AccessControlType]::Allow,
		[System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
	)

	# bf967a86-0de6-11d0-a285-00aa003049e2 Computer object type
	[System.Byte[]]$SchemaObjectId = Get-ADObject -Filter 'name -eq "Computer"' -SearchBase ((Get-ADRootDSE).schemaNamingContext) -Properties schemaIDGUID | Select -ExpandProperty schemaIDGUID
	$Guid = New-Object -TypeName System.Guid(,$SchemaObjectId)

	[System.DirectoryServices.ActiveDirectoryAccessRule]$CreateComputerAce = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule(
		$Sid, 
		@([System.DirectoryServices.ActiveDirectoryRights]::CreateChild),
		[System.Security.AccessControl.AccessControlType]::Allow,
		$Guid,
		[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
	)

	$OU = $Using:Path

	if ([System.String]::IsNullOrEmpty($OU))
	{
		$DN = $CNO | Select-Object -ExpandProperty DistinguishedName
		$OU = $DN.Substring($DN.IndexOf(",") + 1)
	}
	else
	{
		$Regex = "^(?:(?<name>CN=[^,]+),)?(?:(?<path>(?:CN|OU)=[^,]+,?)+,)?(?<domain>DC=[^,]+,?)+$"

		if ($OU -notmatch $Regex)
		{	
			[System.String[]]$DN = Get-ADObject -Filter { ((objectClass -eq "organizationalUnit") -or (objectClass -eq "container")) -and (name -eq $OU) } | Select-Object -ExpandProperty DistinguishedName

			if ($DN -eq $null)
			{
				throw New-Object -TypeName System.ArgumentException("The provided OU name, $Item, could not be found", "Path")
			}

			if ($DN.Length -gt 1)
			{
				throw New-Object -TypeName System.ArgumentException("The provided OU name, $Item, matched more than 1 OU", "Path")
			}

			$OU = $DN
		}		
	}

	[System.DirectoryServices.ActiveDirectorySecurity]$Acl = Get-Acl -Path "AD:\$OU"
	$Acl.AddAccessRule($ReadAce)
	$Acl.AddAccessRule($CreateComputerAce)
	Set-Acl -Path "AD:\$OU" -AclObject $Acl
} @Splat