[CmdletBinding()]
Param(
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String]$DomainName,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[System.String]$DelegateServer = "*"
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

if ([System.String]::IsNullOrEmpty($DomainName))
{
	$DomainName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Domain
}

$Delegate = "$DelegateServer.$DomainName"

Enable-WSManCredSSP -Role Client -DelegateComputer $Delegate -Force
Enable-WSManCredSSP -Role Server -Force

$ParentKey =  "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
$Key = "$ParentKey\CredentialsDelegation"
$FreshKey = "$Key\AllowFreshCredentials"
$NTLMKey = "$Key\AllowFreshCredentialsWhenNTLMOnly"

# Sometimes Enable-WSManCredSSP doesn't get it right, so we set some registry entries by hand
New-Item -Path $ParentKey -Name "CredentialsDelegation" -Force
New-Item -Path $Key -Name "AllowFreshCredentials" -Force
New-Item -Path $key -Name "AllowFreshCredentialsWhenNTLMOnly" -Force
New-ItemProperty -Path $Key -Name "AllowFreshCredentials" -Value 1 -PropertyType Dword -Force
New-ItemProperty -Path $Key -Name "ConcatenateDefaults_AllowFresh" -Value 1 -PropertyType Dword -Force
New-ItemProperty -Path $Key -Name "AllowFreshCredentialsWhenNTLMOnly" -Value 1 -PropertyType Dword -Force
New-ItemProperty -Path $Key -Name "ConcatenateDefaults_AllowFreshNTLMOnly" -Value 1 -PropertyType Dword -Force
New-ItemProperty -Path $FreshKey -Name 1 -Value "WSMAN/$DelegateServer" -PropertyType String -Force
New-ItemProperty -Path $NTLMKey -Name 1 -Value "WSMAN/$DelegateServer" -PropertyType String -Force
New-ItemProperty -Path $FreshKey -Name 2 -Value "WSMAN/$Delegate" -PropertyType String -Force
New-ItemProperty -Path $NTLMKey -Name 2 -Value "WSMAN/$Delegate" -PropertyType String -Force