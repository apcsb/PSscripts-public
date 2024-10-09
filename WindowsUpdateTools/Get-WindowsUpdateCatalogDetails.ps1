<#
This PowerShell script queries the followint MS Graph API endpoint  with various parameters:
    https://graph.microsoft.com/beta/admin/windows/updates/catalog/entries
The data will be returned in a variery of ways: grid view, file (JSON, CSV) or pipe it to another command.
The script runs under delegated permissions - the user will be prompted to authenticate
    Graph API scope required to run: WindowsUpdates.ReadWrite.All
Filter validation will not be performed

References:
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/enhance-update-management-decisions-with-metadata-and-insights/ba-p/3903474
https://learn.microsoft.com/en-us/graph/api/resources/windowsupdates-qualityupdatecatalogentry?view=graph-rest-beta

The following parameters are available:
* Type: type of the update
    Type: string
    Possible Values:
    - Quality (default)
    - Feature

* Classification: classification of the Quality update (feature updates don't have them)
    Type: string
    Default: empty and not included in the query [optional parameter]
    Possible Values:     
    - all
    - security
    - nonSecurity
    - unknownFutureValue
    microsoft.graph.windowsUpdates.qualityUpdateClassification	
* Cadence: cadence of the Quality update (feature updates don't have them)
    Type: string
    Default: empty and not included in the query [optional parameter]
    Possible Values:     
    - monthly
    - outOfBand
    - unknownFutureValue
    microsoft.graph.windowsUpdates.qualityUpdateCadence

* CVSS: The minimum CVSS score to return in the format of "1.0".
    Type: Float (range 0.0 - 10.0)
    Default: empty and not included in the query [optional parameter]
    Corresponds to ODATA property "filter= microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/cveSeverityInformation/maxBaseScore gt X"
    Possible values: 0.0 - 10.0

* ExploitedCVEs: A comma-separated string or an array of CVEs that have been exploited.
    Type: string.
    Default: empty and not included in the query [optional parameter]
    Corresponds to ODATA property "filter= microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/exploitedCVEs/any(cve: cve eq 'CVE-2020-1234' or cve eq 'CVE-2020-5678')"

* TenantId: The tenant ID to query. 
    Type: string.
    Optional

* Output-type: The type of the output. 
    Type: string.
    Default: GridView
    Possible values:
    - GridView (default)
    - JSON
    - CSV
    - Pipe

* OrderBy: The property to order the results by.
    Type: string.
    Corresponds to ODATA "orderby=X".
    Default: empty and not included in the query [optional parameter]
    Possible values:
    - CVE
    - ReleaseDate (default)
    - CVSS
    - DisplayName

* Top: The maximum number of results to return. 
    Type: integer
    Default: empty and not included in the query [optional parameter]
    Corresponds to ODATA "top=X".

#>

#define the script parameters
[CmdletBinding()]
param (
    [Parameter()][ValidateSet("Quality", "Feature")][string]$Type="Quality",
    [Parameter()][ValidateSet("all", "security", "nonSecurity", "unknownFutureValue")][string]$Classification,
    [Parameter()][ValidateSet("monthly", "outOfBand", "unknownFutureValue")][string]$Cadence,
    [Parameter()][string]$ExploitedCVEs,
    [Parameter()][float]$CVSS,
    
    [Parameter()][ValidateSet("CVE", "ReleaseDate", "DisplayName", "CVSS")][string]$OrderBy,
    [Parameter()][int]$Top,
    
    [Parameter()][string]$TenantId, #= "<YOUR VALUE HERE>", #remove the first commend and add your tenant ID to make life easier
    [Parameter()][string]$ClientId, #= "<YOUR VALUE HERE>", #this is only necessary if you can't work with the standard Graph PowerShell application. Likely you would not need it.

    [Parameter()][ValidateSet("GridView", "JSON", "CSV", "Pipe")][string]$OutputType = "GridView"
)

#Connect to graph using user's credentials (delegate permissions)
$GraphParams = @{
    Scopes = "WindowsUpdates.ReadWrite.All"
}
if ($TenantId) { $GraphParams.Add("TenantId", $TenantId) }
if ($ClientId) { $GraphParams.Add("ClientId", $ClientId) }

Connect-MgGraph @GraphParams -NoWelcome

if ($null -eq (Get-MgContext).Account) {
    Write-Error "Failed to connect to Graph API. Please check your credentials and try again"
    exit
}

#this will bug out if the Scopes contains more than one scope, but currently we don't care :)
if ((Get-MgContext).Scopes -notcontains $GraphParams.Scopes) {
    Write-Error "Required Graph API permissions $($GraphParams.Scopes) are missing!`n Please ensure you have the right permissions and Admin Consent was provided and try again"
    exit
}

#Build the query
$queryParams = @{} #will store all the parameters key-value pairs
$queryFilters = New-Object System.Collections.Generic.List[System.String] # will store all the components of $filter parameter. We will only support AND


if ($Top        ) { $queryParams.Add("`$top"        , $Top      ) }
if ($OrderBy    ) { $queryParams.Add("`$orderby"    , $OrderBy  ) }

if ($Type) {
    switch ($Type) {
        Quality { 
            $queryFilters.Add("isof('microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry')") 
            $queryParams.Add("`$expand", "microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/productRevisions,microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/cveSeverityInformation/exploitedCves")

            #this controls what will be displayed in the GridView
            $DisplayProperties = @( #what to display and in what order, may become a parameter one day
                'displayName',
                'shortName',
                #let's trim the time from the releaseDateTime and only leave date
                @{Name="releaseDate";Expression={$_.releaseDateTime.ToString().Split(" ")[0]}},
                #'releaseDateTime',
                'qualityUpdateClassification',
                'qualityUpdateCadence',
            #    'isExpeditable', #this is currently always true
            #    'deployableUntilDateTime', # this is currently all empty
            #    'cveSeverityInformation', # this needs expansion
            #    'productRevisions', # this needs expansion
            #    'catalogName', #this is empty for many updates
            #    'id',
            #    '@odata.type',
            #    'productRevisions@odata.context'

                #join all the properties of the productRevisions[x].displayName with a newline separator into a single string
                @{Name="ProductRevisions";Expression={($res[0].productRevisions | foreach-Object { $_.displayName }) -join "`n"}} #this is a calculated property

                #get the CVE max score. If not available, use 0.0
                @{Name="CVSSmax";Expression={if ($_.cveSeverityInformation) { $_.cveSeverityInformation.maxBaseScore } else { "0.0" }}}

                #get the CVEs in the format {number} ({url}). Multiple CVEs should be joined with a newline. If not available, use empty string
                @{Name="CVEs";Expression={if ($_.cveSeverityInformation) { ($_.cveSeverityInformation.exploitedCves | foreach-Object { "$($_.number) ($($_.url))" }) -join "`n" } else { "" }}}
            )
        }
        Feature { 
            
            $queryFilters.Add("isof('microsoft.graph.windowsUpdates.featureUpdateCatalogEntry')")

            #what to display for feature updates. Much less than for Quality updates
            $DisplayProperties = @(
                "displayName",
                "version",
                "buildNumber",
                #let's trim the time from the releaseDateTime and only leave date
                @{Name="releaseDate";Expression={$_.releaseDateTime.ToString().Split(" ")[0]}},

                #let's trim the time from the releaseDateTime and only leave date
                @{Name="deployableUntil";Expression={$_.deployableUntilDateTime.ToString().Split(" ")[0]}}
            )
        }
    }
}

if ($Classification) {
    if ($Type -ne "Quality") {
        Write-Warning "Classification is only applicable to Quality updates. Ignoring the parameter"
    } else {
        $queryFilters.Add("microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/qualityUpdateClassification eq '$Classification'")
    }
}   
if ($Cadence) {
    if ($Type -ne "Quality") {
        Write-Warning "Cadence is only applicable to Quality updates. Ignoring the parameter"
    } else {
        $queryFilters.Add("microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/qualityUpdateCadence eq '$Cadence'")
    }
}

if ($CVSS) {
    $queryFilters.Add("microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/cveSeverityInformation/maxBaseScore gt $($CVSS.ToString('F1'))")    
}

if ($ExploitedCVEs) {
    $exploitedCVEsArr = $ExploitedCVEs -split ","
    $exploitedCvesSubFilter = $exploitedCVEsArr.ForEach({ "cve/number eq '$_'" }) -join " or "
    $exploitedCvesFilter = "microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/cveSeverityInformation/exploitedCves/any(cve: $exploitedCvesSubFilter)"
    $queryFilters.Add($exploitedCvesFilter)
}

#Build the final query string
$baseURI = "https://graph.microsoft.com/beta/admin/windows/updates/catalog/entries"
$query = $baseURI + "?" #add the question mark for parameters
if ($queryFilters.Count -gt 0) { $queryParams.Add("`$filter",$queryFilters -join " and ") }
if ($queryParams.Count -gt 0) { $query += ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "&" }

Write-Verbose "Query: `n$query`n"


#Run the query
$catalog = Invoke-MgGraphRequest -Method GET -Uri $query
Write-Verbose "Query results: $($catalog.value.Count) entries"

if ($catalog.value.Count -eq 0) {
    Write-Warning "No results found"
    return
}
$res = $catalog.value #put the results in a variable for convenience


#based on the output type, produce the output
switch ($OutputType) {
    JSON { $res | ConvertTo-Json -Depth 10 }
    CSV  { Write-Warning "Not yet implemented (CovertTo-CSV crashes)"} #$res | ConvertTo-Csv -NoTypeInformation }
    Pipe { $res }
    default { $res }
    GridView {

        $res | Select-Object -Property $DisplayProperties | Sort-Object -Property releaseDate -Descending | Out-GridView -Title "Update catalog information"

    }
}
exit


