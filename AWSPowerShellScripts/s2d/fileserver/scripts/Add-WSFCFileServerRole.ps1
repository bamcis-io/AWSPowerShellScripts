[CmdletBinding(DefaultParameterSetName = "CredGeneral")]
Param(
	[Parameter(Mandatory = $true, Position = 0)]
	[ValidateNotNullOrEmpty()]
	[ValidateLength(1, 15)]
	[System.String]$Name,

	[Parameter(ParameterSetName = "CredGeneral", Mandatory = $true)]
	[Parameter(ParameterSetName = "PassGeneral", Mandatory = $true)]
	[Parameter(ParameterSetName = "EncryptedPassGeneral", Mandatory = $true)]
	[Parameter(ParameterSetName = "SSMParameterStoreGeneral", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$IPAddress,

	[Parameter(ParameterSetName = "CredGeneral", Mandatory = $true)]
	[Parameter(ParameterSetName = "PassGeneral", Mandatory = $true)]
	[Parameter(ParameterSetName = "EncryptedPassGeneral", Mandatory = $true)]
	[Parameter(ParameterSetName = "SSMParameterStoreGeneral", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$VirtualDisk,

	[Parameter(ParameterSetName = "CredSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "PassSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "EncryptedPassSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "SSMParameterStoreSOFS", Mandatory = $true)]
	[Switch]$SOFS,

	[Parameter(ParameterSetName = "CredSOFS")]
	[Parameter(ParameterSetName = "CredGeneral")]
	[ValidateNotNull()]
	[System.Management.Automation.Credential()]
	[System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

	[Parameter(ParameterSetName = "PassSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "PassGeneral", Mandatory = $true)]
	[Parameter(ParameterSetName = "EncryptedPassSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "EncryptedPassGeneral", Mandatory = $true)]
	[Parameter(ParameterSetName = "SSMParameterStoreSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "SSMParameterStoreGeneral", Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Username,

	[Parameter(ParameterSetName = "PassSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "PassGeneral", Mandatory = $true)]
	[ValidateNotNull()]
	[System.String]$Password,

	[Parameter(ParameterSetName = "EncryptedPassSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "EncryptedPassGeneral", Mandatory = $true)]
	[System.String]$KMSEncryptedPassword,

	[Parameter(ParameterSetName = "SSMParameterStoreSOFS", Mandatory = $true)]
	[Parameter(ParameterSetName = "SSMParameterStoreGeneral", Mandatory = $true)]
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

	switch -Wildcard ($PSCmdlet.ParameterSetName)
	{
		"Pass*" {
			# Do nothing		
			break
		}
		"EncryptedPass*" {
			[System.Byte[]]$Bytes = [System.Convert]::FromBase64String($KMSEncryptedPassword)
			[System.IO.MemoryStream]$MStream = New-Object -TypeName System.IO.MemoryStream($Bytes, 0, $Bytes.Length)
			[Amazon.KeyManagementService.Model.DecryptResponse]$Response = Invoke-KMSDecrypt -CipherTextBlob $MStream
			$Password = [System.Text.Encoding]::UTF8.GetString($Response.PlainText.ToArray())

			break
		}
		"SSMParameterStore*" {
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
	if ($Using:SOFS)
	{
		Add-ClusterScaleOutFileServerRole -Name $Using:Name
	}
	else
	{
	
		Function Get-NextAvailableDriveLetter {
			[CmdletBinding()]
			Param(
				[Parameter()]
				[Switch]$Descending
			)

			Begin {
				[System.Char[]]$Letters = "defghijklmnopqrstuvwxyz".ToCharArray()
				[System.Char[]]$ReverseLetters = "zyxwvutsrqponmlkjihgfed".ToCharArray()
			}

			Process {
				$Set = $Letters
				if ($Descending) {
					$Set = $ReverseLetters
				}

				foreach ($Char in $Set)
				{
					if (-not (Test-Path "$Char`:\"))
					{
						Write-Output -InputObject $Char
						break
					}
				}
			}

			End {
			}
		}

		# General File Shares can't be run on a CSV, so move the CSV to this node,
		# remove it from the CSV and assign a drive letter to it
		[Microsoft.FailoverClusters.PowerShell.ClusterSharedVolume]$CSV = Move-ClusterSharedVolume -Name "Volume1" -Node $env:COMPUTERNAME
		$CSVInfo = $CSV | Select-Object -ExpandProperty SharedVolumeInfo | Select-Object -ExpandProperty Partition | Select-Object -Property Name,PartitionNumber
		Get-Disk | Get-Partition | Where-Object { $_.PartitionNumber -eq $CSVInfo.PartitionNumber -and (Get-Volume -Partition $_).UniqueId -eq $CSVInfo.Name }	
		[Microsoft.Management.Infrastructure.CimInstance]$CSVPartition = Get-Disk | Get-Partition | Where-Object { $_.PartitionNumber -eq $CSVInfo.PartitionNumber -and (Get-Volume -Partition $_).UniqueId -eq $CSVInfo.Name }

		Remove-ClusterSharedVolume -InputObject $CSV | Out-Null

		Set-Partition -NewDriveLetter (Get-NextAvailableDriveLetter) -InputObject $CSVPartition

		[System.Collections.Hashtable]$InsideSplat = @{}

		if ($Using:IPAddress -ne $null -and $Using:IPAddress.Length -gt 0)
		{
			$InsideSplat.Add("StaticAddress", $Using:IPAddress)
		}

		Add-ClusterFileServerRole -Storage $Using:VirtualDisk -Name $Using:Name @InsideSplat
	}
} @Splat