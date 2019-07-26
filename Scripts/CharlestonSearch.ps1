param(
    $APIKey
)

$SearchArguments = @{
    ApiKey  = $APIKey
    City    = "Charleston"
    State   = "SC"
    # Port    = "8080"
    Product = 'Tomcat'
}

$Results = (Search-Shodan @SearchArguments).matches

$Hosts = New-Object System.Collections.ArrayList

$Results | ForEach-Object {
    $HostResult = [PSCustomObject]@{
        Domains     = $_.domains | select -First 1
        IP          = $_.ip_str
        Time        = $_.timestamp
        Latitude    = $_.location.latitude
        Longitude   = $_.location.longitude
    }

    $Hosts.Add($HostResult) | Out-Null
}

Write-Output $Hosts