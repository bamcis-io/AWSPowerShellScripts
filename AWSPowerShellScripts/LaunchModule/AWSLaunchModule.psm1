# Dot-source all functions from scripts
$Scripts = @( Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue )
foreach ($Script in $Scripts)
{
    try
    {
        . $Script.Fullname
    }
    catch
    {
        Write-Error -Message "Failed to import script $($Script.Fullname): $_.Exception.Message"
        return
    }
}

Export-ModuleMember -Function *