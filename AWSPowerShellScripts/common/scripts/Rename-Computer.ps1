Param(
	[Parameter(Position = 0, Mandatory = $true)]
	[ValidateLength(0,15)]
	[System.String]$NewName = [System.String]::Empty,

	[Parameter()]
	[Switch]$Restart
)

Start-Transcript -Path "$env:ProgramData\Amazon\Logs\$(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf).txt" -Append
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

if (-not [System.String]::IsNullOrEmpty($NewName)) 
{
	[System.Collections.Hashtable]$Splat = @{}

	if ($Restart)
	{
		$Splat.Add("Restart", $true)
	}

	Rename-Computer -NewName $NewName -Force @Splat
}
else
{
	Write-Verbose -Message "No new name supplied to Rename-Computer.ps1"
}