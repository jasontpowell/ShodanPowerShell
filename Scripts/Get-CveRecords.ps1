function Get-CveRecords {
    [CmdletBinding()]
    param(
        # Path to folder containing CVE json files
        $Path
    )

    $CVERecords = New-Object System.Collections.ArrayList 

    $Path | Get-ChildItem -Filter "*.json" | ForEach-Object {
        $CVEs = Get-Content -Raw -Path $($_.FullName) | ConvertFrom-Json
        
        $CVEs.CVE_Items | ForEach-Object {
            $CVE = $_.cve.CVE_data_meta.ID
            $Impact = $_.impact.baseMetricV2.severity
            
            $_.cve.affects.vendor.vendor_data | ForEach-Object {
                $Vendor = $_.vendor_name
               
                $_.product.product_data | ForEach-Object {
                    $Product = $_.product_name
    
                    $_.version.version_data.version_value | ForEach-Object {
                        $CveRecord = [pscustomobject]@{
                            CVE     = $CVE
                            Impact  = $Impact
                            Vendor  = $Vendor
                            Product = $Product
                            Version = $_
                        }
                
                        $CVERecords.Add($CveRecord) | Out-Null
                    }
                }
            }
        }
    }

    Write-Output $CVERecords
}
