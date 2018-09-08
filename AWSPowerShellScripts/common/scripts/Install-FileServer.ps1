[CmdletBinding()]
Param()

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

Install-WindowsFeature -Name Storage-Services,FS-FileServer,FS-Data-Deduplication,FS-Resource-Manager -IncludeManagementTools
