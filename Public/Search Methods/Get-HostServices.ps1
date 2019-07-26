function Get-HostServices {
    <#
    .SYNOPSIS
        Returns all services that have been found on the given host IP.

    .DESCRIPTION
        Long description

    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does

    .INPUTS
        System.Int32
            You can pipe an Int32 object to this function for the IP parameter.

    .OUTPUTS
        System.Object
            This function returns an object that represents the host information.
            These objects have the following properties:

    .NOTES
        General notes
    #>

    [CmdletBinding()]
    param(

        # Host IP address
        [Parameter()]
        $IP,

        # True if all historical banners should be returned
        [Parameter()]
        [Switch]
        $History,

        # True to only return the list of ports and the general host information, no banners
        [Parameter()]
        [Switch]
        $Minify,

        # A valid Shodan API key
        [Parameter()]
        [SecureString]
        $ApiKey
    )

    begin {}

    process {
        $QueryParameters = New-Object Hashtable

        $Method = "get"
        $BaseUri = "https://api.shodan.io"
        $Path = "/shodan/host/$IP"

        $QueryParameters["key"] =  [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey))

        if ($History) {
            $QueryParameters["history"] = $true
        }

        if ($Minify) {
            $QueryParameters["minify"] = $true
        }


        $RequestArgs = @{
            Method  = $Method
            Uri     = $BaseUri + $Path
            Body    = $QueryParameters
        }

        try {
            $Response = Invoke-WebRequest @RequestArgs -ErrorAction Stop
         
            $QueryParameters["key"] = $null
            [System.GC]::Collect()

            $ResponseContent = $Response.Content | ConvertFrom-Json
    
            Write-Output $ResponseContent
        }
        catch {
            # $StatusCode = $($_.Exception.Response.StatusCode.value__)                
            # $Message = $_.ToString()
            # $Headers = $_.Exception.Response.Headers
            $ErrorObject = $PSItem

            $PSCmdlet.ThrowTerminatingError($ErrorObject)
        }
    }

    end {}
}
