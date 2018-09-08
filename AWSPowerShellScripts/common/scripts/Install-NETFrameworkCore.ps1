[CmdletBinding()]
Param(
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$Retries = 0
$Installed = $false
  
do {
	try {
		Install-WindowsFeature NET-Framework-Core
        $Installed = $true
    }
    catch [Exception] {

		$Retries++
          
		if ($Retries -lt 6) {
            Write-Warning $_.Exception.Message
            $LinearBackoff = $Retries * 60
            Write-Warning "Installation failed. Retrying in $LinearBackoff seconds."
            Start-Sleep -Seconds $LinearBackoff
        }
    }
} while (($Retries -lt 6) -and (-not $Installed))
   
if (-not $Installed)
{
	Write-Error -Message "Failed to install .NET Framework."
}