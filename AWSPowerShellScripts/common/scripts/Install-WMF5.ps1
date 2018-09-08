[CmdletBinding()]
Param()

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

# Supported Operating Systems
$WS2008R2_MAJOR                 = "6.1"
$WS2012_MAJOR                   = "6.2"
$WS2012R2_MAJOR                 = "6.3"
$WS2016_MAJOR                   = "10.0"

if ($PSVersionTable.PSVersion.Major -lt 5) 
{
	Write-Verbose -Message "WMF 5 is not installed, installing now."

	$MajorOSVersion = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property @{Name = "Major"; Expression = {$_.Version.Split(".")[0] + "." +$_.Version.Split(".")[1]}} | Select-Object -ExpandProperty Major

	switch ($MajorOSVersion) {
		$WS2016_MAJOR {
			$Url = [System.String]::Empty
			$PackageId = [System.String]::Empty
			break
		}
		$WS2012R2_MAJOR {
			$Url = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu" # WMF 5.1
			$PackageId = "KB3191564"
			break
		}
		$WS2012_MAJOR {
			$Url = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/W2K12-KB3191565-x64.msu" # WMF 5.1
			$PackageId = "KB3191565"
			break
		}
		$WS2008R2_MAJOR {
			# $Url = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip"
			$Url = "https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/Win7AndW2K8R2-KB3134760-x64.msu" # WMF 5.0
			$PackageId = "KB3134760"
			break
		}
		default {
			Write-Warning -Message "Cannot match current Major OS Version, $MajorOSVersion, for WMF installation."
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
	Write-Verbose -Message "PowerShell version $($PSVersionTable.PSVersion.Major) detected, WMF5 already installed."
}
