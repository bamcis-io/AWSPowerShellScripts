[CmdletBinding()]
Param(
	[Parameter()]
	[ValidateRange(0, [System.Int32]::MaxValue)]
	[System.Int32]$BaseProcessorNumber = 0
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$TaskName = "Set-NetAdapterRss"

[System.String]$Command = @"
`$Net = Get-NetAdapter
`$MaxvCPU = Get-CimInstance -ClassName Win32_Processor -Property NumberOfLogicalProcessors | Select-Object -ExpandProperty NumberOfLogicalProcessors
`$Base = $BaseProcessorNumber

if (`$Base -ge `$MaxvCPU)
{
	throw (New-Object -TypeName System.ArgumentException("The base processor must be less than the number of virtual CPUs, `$MaxvCPU."))
}

foreach (`$Adapter in `$Net)
{	
	try 
	{
		`$Id = `$Adapter.PnPDeviceId.Replace("\", "\\")
		`$Inf = Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DeviceID = '`$Id'" | Select-Object -ExpandProperty InfName
		`$File = Get-WindowsDriver -Online -Driver `$Inf | Select-Object -First 1 | Select-Object -ExpandProperty OriginalFileName
		`$FileName = [System.IO.Path]::GetFileName(`$File)

		switch -Regex (`$FileName)
		{
			"xennet*" {
				# Do nothing, doesn't support Rss
				break
			}
			"ena*" {
				`$Adapter | Set-NetAdapterRss -BaseProcessorNumber `$Base -MaxProcessors `$MaxvCPU
				break
			}
			"vxn*" {
				`$Adapter | Set-NetAdapterRss -BaseProcessorNumber `$Base -MaxProcessors `$MaxvCPU
				break
			}
		}
	}
	catch [Exception]
	{
		Write-Warning -Message "Error setting Rss on `$(`$Adapter.Name) : `$(`$_.Exception.Message)"
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