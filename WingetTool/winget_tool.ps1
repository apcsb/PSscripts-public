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
    [parameter(Mandatory=$false)][String]$CertSubject = "<CERT_SUBJECT_HERE>",

   #parameters for AAD Tenant (Win32 Upload, maybe more later)
    [parameter(Mandatory=$false)][String]$AAD_TenantID     = "<TENANT_ID_HERE>",
    [parameter(Mandatory=$false)][String]$AAD_ClientID     = "<CLIENT_ID_HERE>",
    #order of preference: Cert (name -or thumb, searched in CurrentUser and LocalMachine, 1st match), ClientSecret
    [parameter(Mandatory=$false)][String]$AAD_ClientCertName = "<CERT_ID_HERE>",
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

    #create the checkscript
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


    # Package MSI as .intunewin file
    #$SourceFolder = "C:\Win32Apps\Source\7-Zip"
    #$SetupFile = "7z1900-x64.msi"
    #$OutputFolder = "C:\Win32Apps\Output"
    #$Win32AppPackage = New-IntuneWin32AppPackage -SourceFolder $SourceFolder -SetupFile $SetupFile -OutputFolder $OutputFolder -Verbose

    # Get meta data from .intunewin file
    #$IntuneWinFile = $Win32AppPackage.Path
    #$IntuneWinMetaData = Get-IntuneWin32AppMetaData -FilePath $IntuneWinFile

    # Create custom display name like 'Name' and 'Version'
    #$DisplayName = $IntuneWinMetaData.ApplicationInfo.Name + " " + $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductVersion
    #$Publisher = $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiPublisher

    # Create requirement rule for all platforms and Windows 10 20H2
    #$RequirementRule = New-IntuneWin32AppRequirementRule -Architecture "x64" -MinimumSupportedWindowsRelease "20H2"  
  
    # Create MSI detection rule
    #$DetectionRule = New-IntuneWin32AppDetectionRuleMSI -ProductCode $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductCode -ProductVersionOperator "greaterThanOrEqual" -ProductVersion $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductVersion
    #$DetectionRule = New-IntuneWin32AppDetectionRuleScript -ScriptFile $CheckScript -EnforceSignatureCheck $true
    
    # Create custom return code
    #$ReturnCode = New-IntuneWin32AppReturnCode -ReturnCode 1337 -Type "retry"

    # Convert image file to icon
    #$ImageFile = ".\$($PackageID)_Icon.png"
    $ImageFile = if ($IconFile) { $IconFile } else { 
       if ($img = Get-ChildItem ".\$($PackageID)_Icon.*") {$img[0].FullName} else {$null}
    }
    log_msg "ImageFile: [$ImageFile]"
    #$Icon = New-IntuneWin32AppIcon -FilePath $ImageFile

    #Parameters for method call

	# we sorta implement two default values here in a pretty ugly fashion, but it works
    $Win32App_Params = @{
        FilePath    = if ($IntuneWinFile ) { $IntuneWinFile } else {
    		if (Test-Path -LiteralPath ".\winget_wrapper.intunewin" -PathType Leaf) {".\winget_wrapper.intunewin"}
			else {".\WinGetWrapper.IntuneWin\setup.intunewin"}
		}
        DisplayName = if ($DisplayName   ) { $DisplayName   } else {$PackageID}
        Description = if ($Description   ) { $Description   } else {$PackageID}
        Publisher   = if ($Publisher     ) { $Publisher     } else {$PackageID}
        AppVersion  = if ($PackageVersion) { $PackageVersion} else {$null     }   # optional
        
        InstallExperience = if ($InstallScope -eq "user") { "user"} else {"system"} #InstallScope may be undefined or "machine" - will resolve to syetem anyway
        RestartBehavior   = $RestartBehavior
        
        InstallCommandLine   = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -executionpolicy bypass -File winget_wrapper.ps1 -Action Install -PackageID $($PackageID) -PackageVersion $($PackageVersion)"
        UninstallCommandLine = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -executionpolicy bypass -File winget_wrapper.ps1 -Action Uninstall -PackageID $($PackageID) -PackageVersion $($PackageVersion)"
        DetectionRule = New-IntuneWin32AppDetectionRuleScript -ScriptFile $CheckScript -EnforceSignatureCheck $true

        RequirementRule = New-IntuneWin32AppRequirementRule -Architecture "x64" -MinimumSupportedWindowsRelease "20H2"
        #ReturnCode = New-IntuneWin32AppReturnCode -ReturnCode 1337 -Type "retry"
        Icon = if ($ImageFile) {New-IntuneWin32AppIcon -FilePath $ImageFile} else {$null}
        
    }

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
	elseif (Test-Path -LiteralPath ".\WingetWrapper\winget_wrapper.ps1" -PathType Leaf) {. .\WingetWrapper\winget_wrapper.ps1 -Action "DotSource" -PackageId $PackageID }
	else { throw "winget_wrapper.ps1 not found" }

	#for some reason the parameter-bound variables get redefined after dot sourcing - let's get them back
	foreach ($p in $PsBoundParameters.GetEnumerator()) { Set-Variable -Name $p.Key -Value $p.Value }
	main # Don't look for it here - it is defined in the winget_wrapper.
} #wrapper for dot-sourcing
####