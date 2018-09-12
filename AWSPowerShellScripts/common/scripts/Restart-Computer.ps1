[CmdletBinding()]
Param()

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$Result = Start-Process -FilePath "shutdown.exe" -ArgumentList @("/r", "/t 10") -Wait -NoNewWindow -PassThru

if ($Result.ExitCode -ne 0) {
    Write-Error "[ERROR] shutdown.exe exit code was not 0. It was actually $($Result.ExitCode)."
}