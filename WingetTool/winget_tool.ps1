[cmdletbinding()]
Param
  (
   #key parameters
    [Parameter(Mandatory=$true )][ValidateSet("Install", "Uninstall", "Detect", "GenerateCheck", "UploadWin32App")][string]$Action,
    [parameter(Mandatory=$true )][String]$PackageID, #Winget Package ID
    [parameter(Mandatory=$false)][String]$PackageVersion, #Winget Package Version
   #optional parameters for WinGet 
    [parameter(Mandatory=$false)][ValidateSet("machine", "user")][String]$InstallScope, # = "user",
    [parameter(Mandatory=$false)][String]$WingetSource = "winget",
    [parameter(Mandatory=$false)][String[]]$WingetParamsExtra,
   #codesigning and IntuneWin package creation
    [parameter(Mandatory=$false)][String]$CertSubject = "APC CodeSign",
    [parameter(Mandatory=$false)][String]$IntuneWinFile = "winget_wrapper.intunewin",
    [parameter(Mandatory=$false)][String]$IntuneWinAppUtil = "IntuneWinAppUtil.exe",

   #parameters for AAD Tenant (Win32 Upload, maybe more later)
    [parameter(Mandatory=$false)][String]$AAD_TenantID     = "21755296-e18f-4367-b4f0-bc44af8c07c3",
    [parameter(Mandatory=$false)][String]$AAD_ClientID     = "448813ec-e3e0-4a33-9bb8-1f3c232e5b8c", #PowerShell app
    #order of preference: Cert (name -or thumb, searched in CurrentUser and LocalMachine, 1st match), ClientSecret
    [parameter(Mandatory=$false)][String]$AAD_ClientCertName = "APCAAD",
    [parameter(Mandatory=$false)][String]$AAD_ClientCertThumb,
    [parameter(Mandatory=$false)][String]$AAD_ClientSecret,

   #parameters for Win32 App Upload
    [parameter(Mandatory=$false)][String]$FilePath,
    [parameter(Mandatory=$false)][String]$DisplayName,
    [parameter(Mandatory=$false)][String]$Description,
    [parameter(Mandatory=$false)][String]$Publisher,
    #[parameter(Mandatory=$false)][String]$InstallContext = "system",  # -- see InstallScope
    [parameter(Mandatory=$false)][String]$RestartBehavior = "suppress",
    [parameter(Mandatory=$false)][String]$IconFile,

   #parameters for Win32 App Assignment
    [parameter(Mandatory=$false)][Boolean]$AssignToAllUsers   = $true,
    [parameter(Mandatory=$false)][String ]$AssignIntent       = "available",
    [parameter(Mandatory=$false)][String ]$AssignNotification = "showAll"
  )

#############################
### CREATE A CHECK SCRIPT FOR INTUNE
### BASED ON DO_DETECT
### https://jdhitsolutions.com/blog/powershell/8693/exporting-powershell-functions-to-files/
### DOES NOT GET EXPORTED

function do_generatecheck { 
#$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$fun = "[cmdletbinding()]Param()
`$Action = 'detect'
`$PackageID = '$($PackageID)'
"
if ($PackageVersion) {$fun += "`$PackageVersion = '$($PackageVersion)'`n"}

@(
"main", "do_detect",
"eventlog_init","eventlog_stop","log_msg", "get_winget"
) | Foreach-Object { $fun += "
function $_ {
    $((Get-Item -LiteralPath "function:$($_)").Definition.ToString())
}
`n`n"}

$fun += "main"

#$fun += (Get-Item -LiteralPath "function:do_detect").Definition.ToString() + "`n`n"
#Write-Verbose $fun

$filename = "$($PackageID)"
if ($PackageVersion) {$filename += "_$($PackageVersion)"}
$filename += "_check.ps1"
log_msg "Generating check file $filename"
$fun | Out-File -FilePath $filename -Encoding ascii
log_msg "Signing check file $filename"
$ret = sign_file -FilePath $filename -CertSubject $CertSubject
log_msg "Returning value: $ret"
return $ret
}

function sign_file {
    param ($FilePath, $CertSubject = "APC CodeSign")

    log_msg "FilePath: [$($FilePath)]"
    if (!($FilePath) -or ($false -eq (Test-Path $FilePath -PathType Leaf))) {
	    log_msg -LogSeverity Error -LogMSG "File Path [$($FilePath)] not found. Exiting..."
	    return -2
    }

    # Get the code-signing certificate from the local computer's certificate store with the name *ATA Authenticode* and store it to the $codeCertificate variable.
    log_msg "Cert Subject: [$($CertSubject)]"
    $codeCertificate = Get-ChildItem Cert:\CurrentUser\My\ | Where-Object {$_.Subject -eq "CN=$($CertSubject)"}

    if (!$codeCertificate) { 
     log_msg -LogSeverity Error -LogMSG "Signing Cert [$($CertSubject)] not found. Exiting...";
     return -1
    }
    log_msg "Cert Thumbprint: [$($codeCertificate.Thumbprint)]"

    # TimeStampServer - Specifies the trusted timestamp server that adds a timestamp to your script's digital signature. Adding a timestamp ensures that your code will not expire when the signing certificate expires.
    $res = Set-AuthenticodeSignature -Certificate $codeCertificate -TimeStampServer http://timestamp.digicert.com -FilePath $FilePath
    log_msg "Cert Status/Message: $($res.Status) : $($res.StatusMessage)"

    if ($res.Status -ne 0) {
	    log_msg -LogSeverity Error -LogMSG "Error signing: [$($res.Status)][$($res.StatusMessage)]. Exiting..."
	    return -3
    } 

    return 0 #We've done it!
}

###################################
### CREATE A WIN32 APP
### DOES NOT GET EXPORTED
### REQUIRES A MODULE IntuneWin32App
### BASED ON https://github.com/MSEndpointMgr/IntuneWin32App
### Requires permission: https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All
###################################

function do_UploadWin32App {
    log_msg "Starting. Checking for IntuneWin32App module"

    if ($null -eq (Get-InstalledModule -Name IntuneWin32App)) { 
        log_msg "IntuneWin32App module not installed - installing"
        Install-Module -Name "IntuneWin32App" -AcceptLicense 
    } else {
        log_msg "IntuneWin32App module already installed. Continuing..."
    }

    ### Create the checkscript
    #. "winget_wrapper.ps1 -Action GenerateCheck -PackageID $($PackageID)" + $(if ($PackageVersion) {" -PackageVersion $($PackageVersion)"})
    
    $CheckScript = "$($PackageID)" + $(if ($PackageVersion) {"_$($PackageVersion)"}) + "_check.ps1"
    if ($false -eq (Test-Path -PathType Leaf -Path ".\$($CheckScript)")) { 
        log_msg -LogMSG "Check script file $CheckScript not found. Generating..."
        $res = do_generatecheck #TODO check the result and exit if bad
        if ($res -ne 0) { 
            log_msg "Error generating check script. Exiting..."
            return $res
        } else {
            log_msg "Check script generated"
        }
        
    }

    ### Create the IntuneWin file if not already
    # Since the CurrentDirectory for .NET funcrions is not the Working Directory for PS, relative paths must be converted to absolute
    function Get-IntuneWinFile {

        #First check if we have a file passed in explicitly...
        #since we are inside a function, we need to use the correct scope for the PSBoundParameters variable
        if ($script:PSBoundParameters.ContainsKey('IntuneWinFile')) { 
            if (Test-Path -LiteralPath $IntuneWinFile -PathType Leaf) { return $IntuneWinFile}
            else {log_msg -LogSeverity Error -LogMSG "Specified Intunewinfile [$($IntuneWinFile)] not found. Exiting..."; exit -1}
        } 
        
        #If not - look in the default location... 
        if (Test-Path -LiteralPath $IntuneWinFile -PathType Leaf) { return $IntuneWinFile | Convert-Path}
        
        #If not - create a new one and put in the default location for future use
        log_msg "IntuneWinFile not found. Building..."
            
        $New_IntuneWin32AppPackage_params = @{
            SourceFolder = "$($env:TEMP)\WinGetWrapper"
            OutputFolder = "$($env:TEMP)\WinGetWrapper.IntuneWin"
            SetupFile = "winget_wrapper.cmd"
            IntuneWinAppUtilPath = Convert-Path -Path $IntuneWinAppUtil
        }
    
        #check if the folders WinGetWrapper and WinGetWrapper.IntuneWin exist in $env:TEMP and recreate them if exist
        $New_IntuneWin32AppPackage_params.SourceFolder, $New_IntuneWin32AppPackage_params.OutputFolder | Foreach-Object {
            if (Test-Path -LiteralPath $_ -PathType Container) { Remove-Item -LiteralPath $_ -Recurse -Force }
                New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
        #copy the wingetwrapper.ps1 from the current folder into the SourceFolder and create a fake setup file
        Copy-Item -Path ".\winget_wrapper.ps1" -Destination $New_IntuneWin32AppPackage_params.SourceFolder -Force
        #"@exit 0" | Out-File -FilePath "$($SourceFolder)\$($SetupFile)." -Force
        Set-Content -Path "$($New_IntuneWin32AppPackage_params.SourceFolder)\$($New_IntuneWin32AppPackage_params.SetupFile)" -Value "@exit 0" -Force
        $Win32AppPackage = New-IntuneWin32AppPackage @New_IntuneWin32AppPackage_params
        
        #if the Path does not exist - something went wrong, exit
        if (
            (-not $Win32AppPackage) -or 
            ($false -eq (Test-Path -PathType Leaf -Path $Win32AppPackage.Path))
            ) { log_msg -LogSeverity Error -LogMSG "Failed creating the IntuneWin package. Exiting..."; exit -1}
        
        Copy-Item -Path $Win32AppPackage.Path -Destination $IntuneWinFile -Force
        log_msg "IntuneWin32AppPackage created at $IntuneWinFile"

        #cleanup
        Remove-Item -LiteralPath $New_IntuneWin32AppPackage_params.SourceFolder -Recurse -Force -ErrorAction Continue
        Remove-Item -LiteralPath $New_IntuneWin32AppPackage_params.OutputFolder -Recurse -Force -ErrorAction Continue

        return $IntuneWinFile | Convert-Path
    }

    ### This is an EXTREMELY simple YAML parser that flattens the hierarchy, but we don't care
    # It will help us easily populate the app properties
    # note that some "container" values may be empty. I don't care.
    $winget_show = winget show --id $PackageID --disable-interactivity $(if ($PackageVersion) {@("--version", $PackageVersion)})

    $pkginfo = @{}
    $currentKey = ""
    
    foreach ($line in $winget_show.Split("`n")) {
        if ($line -match '^([^:]+):\s*(.*)$') {
            $currentKey = $matches[1].Trim()
            $pkginfo[$currentKey] = $matches[2].Trim()
        }
        elseif ($currentKey -ne "") { $pkginfo[$currentKey] += "`n" + $line.Trim() }
    }
    $pkginfo["DisplayName"] = if ($winget_show | Select-String -Pattern "Found (.*) \[") {
        ($winget_show | Select-String -Pattern "Found (.*) \[").Matches.Groups[1].Value
    } else { $PackageID }
    
#    Remove-Variable currentKey, winget_show #let's clean up

    <# All this stuff is for MSI, we don't need it for WinGet - reference only
    # Create custom display name like 'Name' and 'Version'
    $DisplayName = $IntuneWinMetaData.ApplicationInfo.Name + " " + $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductVersion
    $Publisher = $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiPublisher

    # Create requirement rule for all platforms and Windows 10 20H2
    $RequirementRule = New-IntuneWin32AppRequirementRule -Architecture "x64" -MinimumSupportedWindowsRelease "20H2"  
  
    # Create MSI detection rule
    $DetectionRule = New-IntuneWin32AppDetectionRuleMSI -ProductCode $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductCode -ProductVersionOperator "greaterThanOrEqual" -ProductVersion $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductVersion
    $DetectionRule = New-IntuneWin32AppDetectionRuleScript -ScriptFile $CheckScript -EnforceSignatureCheck $true
    
    # Create custom return code
    $ReturnCode = New-IntuneWin32AppReturnCode -ReturnCode 1337 -Type "retry"
    #>
    
    #check if file $IconFile exists, if yes $ImageFile will be the full path to that file
    
    if ($IconFile) {
        if (Test-Path -LiteralPath $IconFile -PathType Leaf) { $ImageFile = $IconFile }
        else {log_msg -LogSeverity Error -LogMSG "Specified IconFile [$($IconFile)] not found. Exiting..."; exit -1}
    } elseif ($img = Get-ChildItem ".\$($PackageID)_Icon.*") { 
            $ImageFile = $img[0].FullName
            log_msg "Found icon: [$ImageFile]"
    } else { $ImageFile = $null}
    # Convert image file to icon
    #$Icon = New-IntuneWin32AppIcon -FilePath $ImageFile

    #Parameters for method call

    $Win32App_Params = @{
        FilePath    = Get-IntuneWinFile

        #mandatory params
        DisplayName     = if ($DisplayName) {$DisplayName} else { $pkginfo.DisplayName}
        Description     = if ($Description) {$Description} elseif ($pkginfo.Description) {$pkginfo.Description} else {$pkginfo.DisplayName}
        Publisher       = if ($Publisher  ) {$Publisher  } elseif ($pkginfo.Publisher  ) {
                                $pkginfo.Publisher + `
                                $(if ($pkginfo["Publisher Url"]) {"`nURL: " + $pkginfo["Publisher Url"]}) +`
                                $(if ($pkginfo["Publisher Support Url"]) {"`nSupport: " + $pkginfo["Publisher Support Url"]})
                            } else {$PackageID}
        
        #optional parameters. Some of the properties might not exist in $pkginfo, so the parameters will be $null
        #The CMDlet reacts poorly if they are $null or empty - we will need to trim them afterwards in that case
        AppVersion      = if ($PackageVersion ) {$PackageVersion } #we do not specify the version as winget will isntall the latest
        Developer       = if ($Developer      ) {$Developer      } else {$pkginfo.Author}
        Notes           = if ($Notes          ) {$Notes          } else {$pkginfo["Release Notes"]}
        InformationURL  = if ($InformationURL ) {$InformationURL } else {$pkginfo.Homepage}
        PrivacyURL      = if ($PrivacyURL     ) {$PrivacyURL     } else {$pkginfo["Privacy Url"]}
        Icon            = if ($ImageFile      ) {New-IntuneWin32AppIcon -FilePath $ImageFile}
        #CompanyPortalFeaturedApp - maybe one day..
        #CategoryName
        #Owner
        
        InstallExperience = if ($InstallScope -eq "user") { "user"} else {"system"} #InstallScope may be undefined or "machine" - will resolve to syetem anyway
        RestartBehavior   = $RestartBehavior
        
        InstallCommandLine   = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -executionpolicy bypass -File winget_wrapper.ps1 -Action Install -PackageID $($PackageID) $(if ($PackageVersion) {"-PackageVersion $($PackageVersion)"}) -Verbose"
        UninstallCommandLine = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -executionpolicy bypass -File winget_wrapper.ps1 -Action Uninstall -PackageID $($PackageID) $(if ($PackageVersion) {"-PackageVersion $($PackageVersion)"}) -Verbose"
        DetectionRule = New-IntuneWin32AppDetectionRuleScript -ScriptFile $CheckScript -EnforceSignatureCheck $true

        RequirementRule = New-IntuneWin32AppRequirementRule -Architecture "x64" -MinimumSupportedWindowsRelease "20H2"
        #ReturnCode = New-IntuneWin32AppReturnCode -ReturnCode 1337 -Type "retry"
    }
    #if ($ImageFile) { $Win32App_Params.Add("Icon", (New-IntuneWin32AppIcon -FilePath $ImageFile)) }
    #remove all the empty parameters so that the CMDlet doesn't complain
    $nullKeys = $Win32App_Params.Keys | Where-Object {$null -eq $Win32App_Params[$_]} 
    foreach ($key in $nullKeys) { $Win32App_Params.Remove($key) }
    
    log_msg "Win32App parameters built"
    log_msg ($Win32App_Params | Select-Object -Property * -ExcludeProperty DetectionRule, Icon | ConvertTo-Json -Depth 10)

    log_msg "Connecting to tenant: $AAD_TenantID"
    
    $Connect_MSIntuneGraph_params = @{
        TenantID     = $AAD_TenantID
        ClientID     = $AAD_ClientID
    }

    if ($AAD_ClientCertName -or $AAD_ClientCertThumb) {
        if ($cert = Get-ChildItem -Path @("Cert:\CurrentUser\My","Cert:\LocalMachine\My") | Where-Object {($_.Subject -match $AAD_ClientCertName) -or ($_.Thumbprint -eq $AAD_ClientCertThumb)} | Select-Object -First 1) {
            $Connect_MSIntuneGraph_params.Add("ClientCert", $cert)
            log_msg "Found matching cert [$($cert.Thumbprint)] [$($cert.Subject)]"
        } else {
            log_msg "Client certificate Name [$($AAD_ClientCertName)] or Thumb [$($AAD_ClientCertThumb)] not found" -LogType Error
            exit 1
        }
    } elseif ($AAD_ClientSecret) {
        $Connect_MSIntuneGraph_params.Add("ClientSecret", $AAD_ClientSecret)
    } else {
        log_msg "No client secret or certificate provided" -LogType Error
        exit 1
    }

    Connect-MSIntuneGraph @Connect_MSIntuneGraph_params
    
    log_msg "Adding app"
    $Win32App = Add-IntuneWin32App @Win32App_Params
    log_msg "Added app result (filtered properties) `n $($Win32App | Select-Object -Property * -ExcludeProperty rules,detectionRules,largeIcon | ConvertTo-Json -Depth 20)" #PS5 requires -Property *
    
    if (-not $Win32App.id) {
        log_msg "Failed to add app" -LogType Error
        exit 1
    }

    if ($AssignToAllUsers) {
        log_msg "Assigning app"
        $Win32Assign = Add-IntuneWin32AppAssignmentAllUsers -ID $Win32App.id -Intent $AssignIntent -Notification $AssignNotification
        log_msg "Assigned app result `n $($Win32Assign| ConvertTo-Json -Depth 20)"
    }
    
    log_msg "Done"
    return 0
}

#### PROGRAM ENTRY POINT 
If ($MyInvocation.InvocationName -ne ".") { 
	Push-Location -Path $PSScriptRoot
	
	
	# Get the rest of the functionality from the WinGet wrapper. The script will not work without it.
	# look in two locations
	if (Test-Path -LiteralPath ".\winget_wrapper.ps1" -PathType Leaf) {. .\winget_wrapper.ps1 -Action "DotSource" -PackageId $PackageID }
	else {  "winget_wrapper.ps1 not found" }

	#for some reason the parameter-bound variables get redefined after dot sourcing - let's get them back
	foreach ($p in $PsBoundParameters.GetEnumerator()) { Set-Variable -Name $p.Key -Value $p.Value }
	main # Don't look for it here - it is defined in the winget_wrapper.
} #wrapper for dot-sourcing
####