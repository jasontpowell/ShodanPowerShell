param(
    $APIKey
)

$SearchArguments = @{
    ApiKey  = $APIKey
    City    = "Charleston"
    State   = "SC"
    # Port    = "8080"
    # Product = 'Tomcat'
    # Product  = "WEBCAM"
}

$Results = (Search-Shodan @SearchArguments).matches

$Hosts = New-Object System.Collections.ArrayList

$Results | ForEach-Object {
    $HostResult = [PSCustomObject]@{
        Product     = $_.product
        Org         = $_.org
        DeviceType  = $_.devicetype
        Domains     = $_.domains | select -First 1
        IP          = $_.ip_str
        Time        = $_.timestamp
        Latitude    = $_.location.latitude
        Longitude   = $_.location.longitude
        Response    = $_.data -split "`n" | Select-Object -First 1
    }

    $Hosts.Add($HostResult) | Out-Null
}

Write-Output $Hosts