[CmdletBinding()]
Param()

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

try {
	Disable-WSManCredSSP -Role Client
}
catch [Exception] {
	& winrm set winrm/config/client/auth '@{CredSSP="false"}'
}

try {
	Disable-WSManCredSSP -Role Server
}
catch [Exception] {
	& winrm set winrm/config/service/auth '@{CredSSP="false"}'
}

$BasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"

Remove-Item -Path "$BasePath\AllowFreshCredentials" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $BasePath -Name "AllowFreshCredentials" -ErrorAction SilentlyContinue
Remove-Item -Path "$BasePath\AllowFreshCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $BasePath -Name "AllowFreshCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue