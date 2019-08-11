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

$Results = Search-Shodan @SearchArguments

$Hosts = New-Object System.Collections.ArrayList

$Results | ForEach-Object {
    $HostResult = [PSCustomObject]@{
<#         Product         = $_.product
        DeviceType      = $_.devicetype
        Domains         = $_.domains | select -First 1
        IP              = $_.ip_str
        Time            = $_.timestamp
        Latitude        = $_.location.latitude
        Longitude       = $_.location.longitude
        Response        = $_.data -split "`n" | Select-Object -First 1
        Port            = $_.port
        Organization    = $_.org
        ISP             = $_.isp
        Hostname        = $_.hostnames | Select-Object -First 1
        Transport       = $_.transport
        OS              = $_.os
        ASN             = $_.asn
        Data            = $_.data #>
        Server          = $_.http.server -split "/" | Select-Object -First 1
    }

    $Hosts.Add($HostResult) | Out-Null
}

Write-Output $Hosts

$CharlestonResults  |ForEach-Object {
    $HostResult = [PSCustomObject]@{
        Product         = $_.product
        DeviceType      = $_.devicetype
        Domains         = $_.domains | select -First 1
        IP              = $_.ip_str
        Time            = $_.timestamp
        Latitude        = $_.location.latitude
        Longitude       = $_.location.longitude
        Response        = $_.data -split "`n" | Select-Object -First 1
        Port            = $_.port
        Organization    = $_.org
        ISP             = $_.isp
        Hostname        = $_.hostnames | Select-Object -First 1
        Transport       = $_.transport
        OS              = $_.os
        ASN             = $_.asn
        Data            = $_.data
        Server          = $_.http.server -split "/" | Select-Object -First 1
        'Server Version' = ($_.http.server -split "/")[1]
    }

    $Hosts.Add($HostResult) | Out-Null
}
