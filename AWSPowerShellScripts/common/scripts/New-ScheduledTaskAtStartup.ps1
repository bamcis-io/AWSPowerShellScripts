[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[System.String]$Name,

	[Parameter(Mandatory = $true, ParameterSetName = "File")]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({
		Test-Path -Path $_
	})]
	[System.String]$File,

	[Parameter(ParameterSetName = "File")]
	[ValidateNotNullOrEmpty()]
	[System.String[]]$Args,

	[Parameter(Mandatory = $true, ParameterSetName = "Encoded")]
	[ValidateNotNullOrEmpty()]
	[System.String]$EncodedCommand,

	[Parameter(Mandatory = $true, ParameterSetName = "Command")]
	[ValidateNotNullOrEmpty()]
	[System.String]$Command
)

switch ($PSCmdlet.ParameterSetName)
{
	"Command" {
		$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
		$EncodedCommand = [Convert]::ToBase64String($Bytes)
		$STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
	}
	"EncodedCommand" {
		# Do Nothing
		$STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -EncodedCommand $EncodedCommand"
	}
	"File" {
		$STParams = "-NonInteractive -WindowStyle Hidden -NoProfile -NoLogo -File `"$File`""

		if ($Args -ne $null -and $Args.Length -gt 0)
		{
			$STParams += " $([System.String]::Join(" ", $Args))"
		}
	}
}

$STSource =  "$env:SYSTEMROOT\System32\WindowsPowerShell\v1.0\powershell.exe"
$STAction = New-ScheduledTaskAction -Execute $STSource -Argument $STParams
$STPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$STSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -MultipleInstances IgnoreNew
$STTrigger = New-ScheduledTaskTrigger -AtStartup
$ScheduledTask = Register-ScheduledTask -TaskName $Name -Action $STAction -Principal $STPrincipal -Settings $STSettings -Trigger $STTrigger -ErrorAction Stop

Write-Host "Scheduled task, $Name, has been created and will execute at startup"