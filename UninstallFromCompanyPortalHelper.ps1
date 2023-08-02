<#
.SYNOPSIS
    This script helps review and enable the newly released Intune feature "Allow manual uninstallation of app via Company Portal".
.DESCRIPTION
    This script can do the following:
    * Export (Review): connects to Intune and exports into two CSV files all apps that do not have an uninstall command, and all apps that do have an uninstall command. You can reviews these lists and take actions.
    
    * Update (Import): imports the data from Intune or a  CSV file (which can be generated by the review mode), updates the uninstall command based on the file contents and enables the manual uninstall switch.
    
    Both modes can be used simlutaneously, if you are 100% solid on your uninstall lines.
    
    The script was developed for Graph PowerShell SDK 1.0, but might work with 2.0 as well (it uses Graps Beta endpoints).
.PARAMETER Export
    Indicated that the data must be saved to CSV files in the current directory.
.PARAMETER UpdateFromFile
    Specifies the path to the CSV file containing the list of apps to enable uninstall for. 
    * Must contain ID. 
    * Other parameters are DisplayName (then you will see names instead of IDs) and UninstallCommandLine (will overwrite if present and differs from the one in Intune). 
    * There are no sanity checks on the command line!
    * The file generated by this script will do.
    Cannot be used with Export
.PARAMETER UpdateFromIntune
    Indicates that the data must be retrieved from Intune and updated there.
    Can be used with Export
.OUTPUTS
    Two CSV files in the current directory, if Export is specified.
    Lots of text output.
.EXAMPLE
    .\Intune-UninstallCommandCheck.ps1 -Export
    Connects to Intune and exports apps with and without an uninstall command to two CSV files in the current directory.
.EXAMPLE
    .\Intune-UninstallCommandCheck.ps1 -UpdateFromIntune
    Uses the data from Intune to enable the manual uninstall switch on all apps with an uninstall command. Make sure your uninstall commands are correct!
.EXAMPLE
    .\Intune-UninstallCommandCheck.ps1 -UpdateFromFile .\apps_with_uninstall.csv
    Imports the CSV file (ex. generated by the review mode), updates the uninstall command (if present in CSV) and enables the manual uninstall switch.
.EXAMPLE
    .\Intune-UninstallCommandCheck.ps1 -UpdateFromIntune -Export
    Uses the data from Intune to enable the manual uninstall switch on all apps with an uninstall command.
    Also exports the list of apps with and without an uninstall command to two CSV files in the current directory for the record.
.NOTES
    Author: Arsen Bandurian
    Version: 2023-08-02-001
#>

[CmdletBinding(DefaultParameterSetName="Intune")]
param
(
    [Parameter(Mandatory = $false, ParameterSetName="Intune")][switch]$Export = $false,
    [Parameter(Mandatory = $false, ParameterSetName="Intune")][switch]$UpdateFromIntune = $false,
    [Parameter(Mandatory = $false, ParameterSetName="File"  )][string]$UpdateFromFile = $null
)
#if no parameters are specified, show help and exit
if ($PSBoundParameters.Count -eq 0) {
    Write-Output "Specify at least one parameter - see help:"
    Write-Output "------------------------------------------"
    Get-Help ".\$($MyInvocation.MyCommand.Name)" -Full
    Write-Output "------------------------------------------"
    exit
}
# Authenticate with Microsoft Graph API
$GraphScopes = if ($UpdateFromIntune.IsPresent -or $UpdateFromFile) { "DeviceManagementApps.ReadWrite.All" } else { "DeviceManagementApps.Read.All"}
Write-Output "### Connecting to Microsoft Graph API with scopes: $($GraphScopes)"
Connect-MgGraph -Scopes $GraphScopes
$res = Get-MgContext
if (!$res.TenantId) {
    Write-Error "Could not connect to Microsoft Graph API. Check your credentials and permissions."
    exit -1
}
#it is nice to have it just in case
$apps = Get-MgDeviceAppManagementMobileApp -Filter "isof('microsoft.graph.win32LobApp')"
if (!$apps) {
    Write-Error "Could not retrieve apps from Intune. Check your permissions."
    exit -1
}
#TODO someday make them parameters as well. Too much fuss.
$filename_without = "apps_without_uninstall.csv"
$filename_with = "apps_with_uninstall.csv"
$appsWithoutUninstall = $apps | Where-Object {($_.AdditionalProperties.uninstallCommandLine -eq $null)} | Select-Object displayName, @{Name="displayVersion"; Expression={$_.AdditionalProperties.displayVersion}},Id | Sort-Object displayName 
if ($appsWithoutUninstall.count) { 
    Write-Output " !! Found $($appsWithoutUninstall.count) apps without an uninstall command"
    if ($Export) {
        Write-Output"  - exporting to $($filename_without))" 
        $appsWithoutUninstall | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath ".\$($filename_without)"
    }    
} else { Write-Output " ++ No apps without an uninstall command found. Seems legit (or you have no apps)" }
$appsWithUninstall = $apps | Where-Object {($_.AdditionalProperties.uninstallCommandLine -ne $null)} | Select-Object displayName, @{Name="displayVersion"; Expression={$_.AdditionalProperties.displayVersion}},Id, @{Name="uninstallCommandLine"; Expression={$_.AdditionalProperties.uninstallCommandLine}} | Sort-Object displayName
if ($appsWithUninstall.count) { 
    Write-Output " -- Found $($appsWithUninstall.count) apps with an uninstall command" 
    if ($Export) {
        Write-Output "  - exporting to $($filename_with)" 
        $appsWithUninstall | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath ".\$($filename_with)"
    }
} else { Write-Output " !! No apps with an uninstall command found" }
#check if an Update parameter was specified
if ($UpdateFromFile -or $UpdateFromIntune.IsPresent) {
    Write-Output "### UPDATE MODE SPECIFIED ###"
 
    if ($UpdateFromIntune) {
        Write-Verbose " -- Using data from Intune."
        $appsToProcess = $appsWithUninstall
    } 
    
    if ($UpdateFromFile) { #check if the file exists
        if (!(Test-Path -Path $UpdateFromFile)) {
            Write-Error " !! No file with app list found at the specified path [$($UpdateFromFile)].`nFix the path or run the script in Export mode to generate one."
            exit -1
        } else {
            Write-Verbose " -- Importing app list from $($UpdateFromFile)"
            $appsToProcess = Import-Csv -Path $UpdateFromFile
        }
    }
    
    #check if every item in the $appsToProcess has an ID
    if ($appsToProcess.count -eq 0) {
        Write-Error "No suitable apps found. Check the import data and try again."
        exit -1
    }
    foreach ($app in $appsToProcess) {
        
        if (!$app.Id) { #mandatory parameter is missing in the CSV
            #concatenate all existing properties of the $app into a single string using | as a separator
            Write-Error "!! Bad input: no ID found for app. Skipping.. Detailed info`n$($app | Format-List | Out-String))`n`n"
            continue
        }
        $displayParam = if ($app.displayName) { $app.displayName } else { $app.Id }
        
        $body = @{
            '@odata.type' = '#microsoft.graph.win32LobApp'
            allowAvailableUninstall =$true
        }
        Write-Output " -- Processing [$($displayParam)]:"
        if ($UpdateFromFile -and $app.uninstallCommandLine) {
            if ($app.uninstallCommandLine -eq ($apps | Where-Object {$_.id -eq $app.id}).AdditionalProperties.uninstallCommandLine) {
                Write-Verbose "  - Uninstall command line for $($displayParam) is already set to [$($app.uninstallCommandLine)] - skipping"
            } else {
                Write-Verbose "  - Updating the uninstall command line to [$($app.uninstallCommandLine)]"
                $body.Add("uninstallCommandLine", $app.uninstallCommandLine)
            }
        }
        
        Write-Verbose "  - Calling Graph API to update the app..."
        $Uri = "/beta/deviceAppManagement/mobileApps/$($app.id)"
        $res = Invoke-MgGraphRequest -Method PATCH -Uri $Uri -Body $body
        #Write-Verbose "  - Done, checking allowAvailableUninstall value:"
        #$check = Invoke-MgGraphRequest -Method GET -Uri $Uri
        #Write-Output "$(if ($check.allowAvailableUninstall) {"OK"} else {"FAIL"} )"
    }
    Write-Output "### IMPORT MODE COMPLETED ###"
    Write-Output "### ALL DONE ###"
}