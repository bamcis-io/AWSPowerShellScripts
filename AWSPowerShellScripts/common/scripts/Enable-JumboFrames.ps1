[CmdletBinding()]
Param(
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.Int32[]]$InterfaceIndex
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$TaskName = "Enable-JumboFrames"

$Adapters = @{
	"PV" = "xennet";
	"ENA" = "ena";
	"INTEL" = "ixgbevf|vxn"
}

if ($InterfaceIndex -ne $null -and $InterfaceIndex.Count -gt 0)
{
	$Val = [System.String]::Join(",", $InterfaceIndex)
	$Condition = "`$true"
}
else
{
	$Val = ""
	$Condition = "`$false"
}

[System.String]$Command = @"
	
	[System.Collections.Hashtable]`$NetSplat = @{}

	if ($Condition)
	{
		`$Indexes = "$Val"
		`$NetSplat.Add("InterfaceIndex", `$Indexes.Split(","))
	}

	`$Net = Get-NetAdapter @NetSplat | Select-Object -Property DriverName,PnPDeviceId,DriverVersion,DriverFileName,Name

	foreach (`$Adapter in `$Net)
	{
		try {
			`$Id = `$Adapter.PnPDeviceId.Replace("\", "\\")
			`$Inf = Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DeviceID = '`$Id'" | Select-Object -ExpandProperty InfName
			`$File = Get-WindowsDriver -Online -Driver `$Inf | Select-Object -First 1 | Select-Object -ExpandProperty OriginalFileName
			`$FileName = [System.IO.Path]::GetFileName(`$File)

			switch -Regex (`$FileName)
			{
				"xennet*" {
					& netsh interface ipv4 set subinterface "`$(`$Adapter.Name)" mtu=9000
					break
				}
				"ena*" {
					Set-NetAdapterAdvancedProperty -Name `$Adapter.Name -RegistryKeyword "MTU" -RegistryValue 9000
					break
				}
				"vxn*" {
					Set-NetAdapterAdvancedProperty -Name `$Adapter.Name -RegistryKeyword "*JumboPacket" -RegistryValue 9014
					break
				}
			}
		}
		catch [Exception]
		{
			Write-Warning "Failed to enable jumbo frames for network adapter `$(`$Adapter.Name)."
		}
	}

	Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:`$false
"@

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$EncodedCommand = [Convert]::ToBase64String($Bytes)
        
$STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
$STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
$STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams
$STPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew
$STTrigger = New-ScheduledTaskTrigger -AtStartup
$ScheduledTask = Register-ScheduledTask -TaskName $TaskName -Action $STAction -Principal $STPrincipal -Settings $STSettings -Trigger $STTrigger -ErrorAction Stop

Write-Host "Scheduled task, $TaskName, has been created and will execute at startup"