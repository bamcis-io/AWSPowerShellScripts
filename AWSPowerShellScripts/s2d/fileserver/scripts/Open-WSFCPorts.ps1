Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

New-NetFirewallRule -Name "WSFC Cluster Communication" -Direction Inbound -Action Allow -Protocol "TCP" -LocalPort 3044 -Profile Any -Enabled True -DisplayName "WSFC Cluster Communication"
