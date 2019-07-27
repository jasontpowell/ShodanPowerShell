function Search-Shodan {
    <#
    .SYNOPSIS
        Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.

    .DESCRIPTION
        Long description

    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does

    .INPUTS

    .OUTPUTS
        System.Object
            This function returns objects that represent query results.
            These objects have the following properties:

    .NOTES
        This method may use API query credits depending on usage. If any of the following criteria are met, your account will be deducated 1 query credit:
            
            1. The search query contains a filter.
            2. Accessing results past the 1st page using the "page". For every 100 results past the 1st page 1 query credit is deducted.
    #>

    [CmdletBinding()]
    param(
        # A valid Shodan API key
        [Parameter()]
        [SecureString]
        $ApiKey,

        # Properties to get summary information on.
        [Parameter()]
        [String[]]
        $Facets,

        # The number of pages to download.  There are 100 results per page.  Default is to download all pages.
        [Parameter()]
        [Int16]
        $Pages,

        # True to only return the list of ports and the general host information, no banners
        [Parameter()]
        [Switch]
        $Minify,

        # Only show results that were collected before the given date.
        [Parameter()]
        [DateTime]
        $Before,

        # Only show results that were collected after the given date.
        [Parameter()]
        [DateTime]
        $After,

        # The Autonomous System Number that identifies the network the device is on.
        [Parameter()]
        [Int32]
        $ASN,

        # Show results that are located in the given city.
        [Parameter()]
        [String]
        $City,

        # Show results that are located within the given country.
        [Parameter()]
        [String]
        $Country,

        # There are 2 modes to the geo filter: radius and bounding box. To limit results based on a radius around a pair of latitude/ longitude, provide 3 parameters; ex: geo:50,50,100. If you want to find all results within a bounding box, supply the top left and bottom right coordinates for the region; ex: geo:10,10,50,50.
        [Parameter()]
        [String]
        $Geo,

        # Hash of the "data" property
        [Parameter()]
        [String]
        $Hash,

        # Only show results that were discovered on IPv6.
        [Parameter()]
        [Switch]
        $HasIPV6,

        # If "true" only show results that have a screenshot available.
        [Parameter()]
        [Switch]
        $HasScreenshot,

        # Search for hosts that contain the given value in their hostname.
        [Parameter()]
        [String]
        $Hostname,

        # Find devices based on the upstream owner of the IP netblock.
        [Parameter()]
        [String]
        $ISP,

        # Find devices depending on their connection to the Internet.
        # TODO: Possible values are: "Ethernet or modem", "generic tunnel or VPN", "DSL", "IPIP or SIT", "SLIP", "IPSec or GRE", "VLAN", "jumbo Ethernet", "Google", "GIF", "PPTP", "loopback", "AX.25 radio modem".
        [Parameter()]
        [String]
        $Link,

        # Search by netblock using CIDR notation; ex: net:69.84.207.0/24
        [Parameter()]
        [String]
        $Net,

        # Find devices based on the owner of the IP netblock.
        [Parameter()]
        [String]
        $Org,

        # Filter results based on the operating system of the device.
        [Parameter()]
        [String]
        $OS,

        # Find devices based on the services/ ports that are publicly exposed on the Internet.
        [Parameter()]
        [Int16]
        $Port,

        # Search by postal code.
        [Parameter()]
        [String]
        $Postal,

        # Filter using the name of the software/ product; ex: product:Apache
        [Parameter()]
        [String]
        $Product,

        # Search for devices based on the state/ region they are located in.
        [Parameter()]
        [String]
        $State,

        # Filter the results to include only products of the given version; ex: product:apache version:1.3.37
        [Parameter()]
        [String]
        $Version,

        # Find Bitcoin servers that had the given IP in their list of peers.
        [Parameter()]
        [String]
        $BitcoinIP,

        # Find Bitcoin servers that return the given number of IPs in the list of peers.
        [Parameter()]
        [Int64]
        $BitcoinIPCount,

        # Find Bitcoin servers that had IPs with the given port in their list of peers.
        [Parameter()]
        [Int16]
        $BitcoinPort,

        # Filter results based on the Bitcoin protocol version.
        [Parameter()]
        [String]
        $BitcoinVersion,

        # Name of web technology used on the website
        [Parameter()]
        [String]
        $HttpComponent,

        # Category of web components used on the website
        [Parameter()]
        [String]
        $HttpComponentCategory,

        # Search the HTML of the website for the given value.
        [Parameter()]
        [String]
        $HttpHtml,

        # Hash of the website HTML
        [Parameter()]
        [String]
        $HttpHtmlHash,

        # Response status code
        [Parameter()]
        [Int16]
        $HttpStatus,

        # Search the title of the website
        [Parameter()]
        [String]
        $HttpTitle,

        # Find NTP servers that had the given IP in their monlist.
        [Parameter()]
        [String]
        $NtpIp,

        # Find NTP servers that return the given number of IPs in the initial monlist response.
        [Parameter()]
        [Int16]
        $NtpIpCount,

        # Whether or not more IPs were available for the given NTP server.
        [Parameter()]
        [Boolean]
        $NtpMore,

        # Find NTP servers that had IPs with the given port in their monlist.
        [Parameter()]
        [String]
        $NtpPort,

        # Search all SSL data
        [Parameter()]
        [Switch]
        $Ssl,

        # Application layer protocols such as HTTP/2 ("h2")
        [Parameter()]
        [String]
        $SslAlpn,

        # Number of certificates in the chain
        [Parameter()]
        [Int16]
        $SslChainCount,

        # Possible values: SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
        [Parameter()]
        [String]
        $SslVersion,

        # Certificate algorithm
        [Parameter()]
        [String]
        $SslCertAlg,

        # Whether the SSL certificate is expired or not
        [Parameter()]
        [Boolean]
        $SslCertExpired,

        # Names of extensions in the certificate
        [Parameter()]
        [String]
        $SslCertExtension,

        # Serial number as an integer or hexadecimal string
        [Parameter()]
        [String]
        $SslCertSerial,

        # Number of bits in the public key
        [Parameter()]
        [Int16]
        $SslCertPubkeyBits,

        # Public key type
        [Parameter()]
        [String]
        $SslCertPubkeyType,

        # SSL version of the preferred cipher
        [Parameter()]
        [String]
        $SslCipherVersion,

        # Number of bits in the preferred cipher
        [Parameter()]
        [Int16]
        $SslCipherBits,

        # Name of the preferred cipher
        [Parameter()]
        [String]
        $SslCipherName,

        # Search all the options
        [Parameter()]
        [String]
        $TelnetOption,

        # The server requests the client to support these options
        [Parameter()]
        [String]
        $TelnetDo,

        # The server requests the client to not support these options
        [Parameter()]
        [String]
        $TelnetDont,

        # The server supports these options
        [Parameter()]
        [String]
        $TelnetWill,

        # The server doesnt support these options
        [Parameter()]
        [String]
        $TelnetWont = $null
    )

    begin {}

    process {
        $QueryParameters = New-Object Hashtable

        # Shodan search query. The provided string is used to search the database of banners in Shodan.
        $Query = New-Object Hashtable

        $MatchResults = New-Object System.Collections.ArrayList

        $Method = "get"
        $BaseUri = "https://api.shodan.io"
        $Path = "/shodan/host/search"

        $QueryParameters["key"] =  [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey))
        $QueryParameters["page"] = $Page 

        if ($Minify) {
            $QueryParameters["minify"] = $true
        }

        if ($null -ne $Before) {
            $Query["before"] = $Before
        }
        
        if ($null -ne $After) {
            $Query["after"] = $After
        }
        
        if ($ASN -ne "") {
            $Query["asn"] = $ASN
        }
        
        if ($City -ne "") {
            $Query["city"] = $City
        }
        
        if ($Country -ne "") {
            $Query["country"] = $Country
        }
        
        if ($Geo -ne "") {
            $Query["geo"] = $Geo
        }
        
        if ($Hash -ne "") {
            $Query["hash"] = $Hash
        }
        
        if ($HasIPV6) {
            $Query["has_ipv6"] = $true
        }
        
        if ($HasScreenshot) {
            $Query["has_screenshot"] = $true
        }
        
        if ($Hostname -ne "") {
            $Query["hostname"] = $Hostname
        }
        
        if ($ISP -ne "") {
            $Query["isp"] = $ISP
        }
        
        if ($Link -ne "") {
            $Query["link"] = $Link
        }
        
        if ($Net -ne "") {
            $Query["net"] = $Net
        }
        
        if ($Org -ne "") {
            $Query["org"] = $Org
        }
        
        if ($OS -ne "") {
            $Query["os"] = $OS
        }
        
        if ($Port -ne "") {
            $Query["port"] = $Port
        }
        
        if ($Postal -ne "") {
            $Query["postal"] = $Postal
        }
        
        if ($Product -ne "") {
            $Query["product"] = $Product
        }
        
        if ($State -ne "") {
            $Query["state"] = $State
        }
        
        if ($Version -ne "") {
            $Query["version"] = $Version
        }
        
        if ($BitcoinIP -ne "") {
            $Query["bitcoin.ip"] = $BitcoinIP
        }
        
        if ($BitcoinIPCount -ne "") {
            $Query["bitcoin.ip_count"] = $BitcoinIPCount
        }
        
        if ($BitcoinPort -ne "") {
            $Query["bitcoin.port"] = $BitcoinPort
        }
        
        if ($BitcoinVersion -ne "") {
            $Query["bitcoin.version"] = $BitcoinVersion
        }
        
        if ($HttpComponent -ne "") {
            $Query["http.component"] = $HttpComponent
        }
        
        if ($HttpComponentCategory -ne "") {
            $Query["http.component_category"] = $HttpComponentCategory
        }
        
        if ($HttpHtml -ne "") {
            $Query["http.html"] = $HttpHtml
        }
        
        if ($HttpHtmlHash -ne "") {
            $Query["http.html_hash"] = $HttpHtmlHash
        }
        
        if ($HttpStatus -ne "") {
            $Query["http.status"] = $HttpStatus
        }
        
        if ($HttpTitle -ne "") {
            $Query["http.title"] = $HttpTitle
        }
        
        if ($NtpIp -ne "") {
            $Query["ntp.ip"] = $NtpIp
        }
        
        if ($NtpIpCount -ne "") {
            $Query["ntp.ip_count"] = $NtpIpCount
        }
        
        if ($NtpMore -ne "") {
            $Query["ntp.more"] = $NtpMore
        }
        
        if ($NtpPort -ne "") {
            $Query["ntp.port"] = $NtpPort
        }
        
        if ($Ssl) {
            $Query["ssl"] = $true
        }
        
        if ($SslAlpn -ne "") {
            $Query["ssl.alpn"] = $SslAlpn
        }
        
        if ($SslChainCount -ne "") {
            $Query["ssl.chain_count"] = $SslChainCount
        }
        
        if ($SslVersion -ne "") {
            $Query["ssl.version"] = $SslVersion
        }
        
        if ($SslCertAlg -ne "") {
            $Query["ssl.cert.alg"] = $SslCertAlg
        }
        
        if ($SslCertExpired -ne "") {
            $Query["ssl.cert.expired"] = $SslCertExpired
        }
        
        if ($SslCertExtension -ne "") {
            $Query["ssl.cert.extension"] = $SslCertExtension
        }
        
        if ($SslCertSerial -ne "") {
            $Query["ssl.cert.serial"] = $SslCertSerial
        }
        
        if ($SslCertPubkeyBits -ne "") {
            $Query["ssl.cert.pubkey.bits"] = $SslCertPubkeyBits
        }
        
        if ($SslCertPubkeyType -ne "") {
            $Query["ssl.cert.pubkey.type"] = $SslCertPubkeyType
        }
        
        if ($SslCipherVersion -ne "") {
            $Query["ssl.cipher.version"] = $SslCipherVersion
        }
        
        if ($SslCipherBits -ne "") {
            $Query["ssl.cipher.bits"] = $SslCipherBits
        }
        
        if ($SslCipherName -ne "") {
            $Query["ssl.cipher.name"] = $SslCipherName
        }
        
        if ($TelnetOption -ne "") {
            $Query["telnet.option"] = $TelnetOption
        }
        
        if ($TelnetDo -ne "") {
            $Query["telnet.do"] = $TelnetDo
        }
        
        if ($TelnetDont -ne "") {
            $Query["telnet.dont"] = $TelnetDont
        }
        
        if ($TelnetWill -ne "") {
            $Query["telnet.will"] = $TelnetWill
        }
        
        if ($TelnetWont -ne "") {
            $Query["telnet.wont"] = $TelnetWont
        }

        $ShodanQueryString = ($Query.GetEnumerator() | ForEach-Object {
                "$($_.Name):'$($_.value)'"
            }) -Join " "

        $QueryParameters["query"] = $ShodanQueryString 
      

        $RequestArgs = @{
            Method  = $Method
            Uri     = $BaseUri + $Path
            Body    = $QueryParameters
        }


        for (($CurrentPage = 1), ($CompletedAllPages = $false); $CompletedAllPages -ne $true; $CurrentPage++) {
            $RequestArgs["Body"]["page"] = $CurrentPage

            try {
                $Response = Invoke-WebRequest @RequestArgs -ErrorAction Stop
                $ResponseContent = $Response.Content | ConvertFrom-Json
                
                $MatchResults.AddRange( $ResponseContent.matches )

                $PageCount = [math]::Round( ($ResponseContent.total / 100), 0 )

                [Int32]$PercentComplete = ( $MatchResults.Count / $ResponseContent.total ) * 100
                $ProgressArgs = @{
                    Activity            = "Downloading results for Shodan query: $ShodanQueryString"
                    CurrentOperation    = "Downloaded $($MatchResults.Count) of $($ResponseContent.total) matches"
                    PercentComplete     = $PercentComplete
                    Status              = "Page $CurrentPage of $PageCount"
                }
    
                Write-Progress @ProgressArgs

                if ($CurrentPage -eq $PageCount -or $CurrentPage -eq $Pages) {
                    $CompletedAllPages = $true
                }

                Start-Sleep -Seconds 1
            }
            catch {
                $Message = $_.ToString() | ConvertFrom-Json | Select-Object -ExpandProperty error
                $ErrorObject = $PSItem

                switch ($Message) {
                    {$_ -like "*request timed out*"} {

                        $ProgressArgs = @{
                            Activity            = "Downloading results for Shodan query: $ShodanQueryString"
                            CurrentOperation    = "Downloaded $($MatchResults.Count) of $($ResponseContent.total) matches"
                            Status              = "The request timed out--retrying in 5 seconds..."
                        }
            
                        Write-Progress @ProgressArgs

                        Start-Sleep -Seconds 5
                        $CurrentPage--
                    }
                    Default {
                        $QueryParameters["key"] = $null
                        [System.GC]::Collect()

                        # TODO: Capture the last page that was successfully downloaded and output it so I can know where to pick up the query next time.
                
                        Write-Output $MatchResults

                        $PSCmdlet.ThrowTerminatingError($ErrorObject)
                    }
                }
            }
        }
               
        $QueryParameters["key"] = $null
        [System.GC]::Collect()

        Write-Output $MatchResults
    }
    end {}
}
