param (
    [bool]$DebugModule = $false
)

# Script-scoped variables
$Script:ModuleRoot  = $PSScriptRoot


# Get public and private function definition files
$Public = @( Get-ChildItem -r -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -r -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

$FilesToLoad = @( [object[]]$Public + [object[]]$Private )


# Dot source the files
foreach($File in $FilesToLoad) {
    Write-Verbose "Importing [$File]"
    try {
        if ($DebugModule) {
            . $File.FullName
        } else {
            . ( [scriptblock]::Create(
                    [io.file]::ReadAllText($File.FullName, [Text.Encoding]::UTF8)
                )
            )
        }
    }
    catch {
        Write-Error -Message "Failed to import function $($File.fullname)"
        Write-Error $_
    }
}
<# 
# Create new Type Accelerators for each Class in the Classes directory
$Accelerators = [powershell].Assembly.GetType("System.Management.Automation.TypeAccelerators")

[String[]]$AcceleratorsToAdd = Get-ChildItem -Recurse -Path $PSScriptRoot\Classes\*.ps1 |
    Select-Object -ExpandProperty BaseName |
    ForEach-Object { Write-Output $_ }

$AcceleratorsToAdd | ForEach-Object {
    $Accelerators::Add($_,$_)
}
 #>