[CmdletBinding()]
Param(
	[Parameter()]
	[System.Boolean]$EnableMultiChannel,

	[Parameter()]
	[System.Boolean]$EnableLargeMtu,

	[Parameter()]
	[Switch]$UpdateRssConnectionCount
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

[System.Collections.Hashtable]$Splat = @{}

if ($UpdateRssConnectionCount)
{
	$Net = Get-NetAdapter | Select-Object -Property DriverName,PnPDeviceId,DriverVersion,DriverFileName,Name

	foreach ($Adapter in $Net)
	{
		try {
			$Id = $Adapter.PnPDeviceId.Replace("\", "\\")
			$Inf = Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DeviceID = '$Id'" | Select-Object -ExpandProperty InfName
			$File = Get-WindowsDriver -Online -Driver $Inf | Select-Object -First 1 | Select-Object -ExpandProperty OriginalFileName
			$FileName = [System.IO.Path]::GetFileName($File)

			switch -Regex ($FileName)
			{
				"xennet*" {
					break
				}
				"ena*" {
					[System.Int32]$RssQCount = Get-NetAdapterAdvancedProperty | Where-Object { $_.DisplayName -like "Maximum Number of RSS Queues" } | Select-Object -First 1 -ExpandProperty RegistryValue
					$Splat.Add("ConnectionCountPerRssNetworkInterface", $RssQCount)
					break
				}
				"vxn*" {
					[System.Int32]$RssQCount = Get-NetAdapterAdvancedProperty | Where-Object { $_.DisplayName -like "Maximum Number of RSS Queues" } | Select-Object -First 1 -ExpandProperty RegistryValue
					$Splat.Add("ConnectionCountPerRssNetworkInterface", $RssQCount)
					break
				}
			}
		}
		catch [Exception]
		{
			Write-Warning "Failed to enable jumbo frames for network adapter $($Adapter.Name)."
		}

		if ($Splat.ContainsKey("ConnectionCountPerRssNetworkInterface"))
		{
			break
		}
	}
}

if ($PSBoundParameters.ContainsKey("EnableMultiChannel"))
{
	$Splat.Add("EnableMultiChannel", $EnableMultiChannel)
}

if ($PSBoundParameters.ContainsKey("EnableLargeMtu"))
{
	$Splat.Add("EnableLargeMtu", $EnableLargeMtu)
}

if ($Splat.Count -gt 0)
{
	Set-SmbClientConfiguration -Confirm:$false -Force @Splat
}
else
{
	Write-Warning -Message "No parameters specified for Set-SmbClient."
}