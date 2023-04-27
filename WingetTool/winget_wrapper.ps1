[cmdletbinding()]
Param
  (
   #most used parameters
    [Parameter(Mandatory=$true )][ValidateSet("Install","Uninstall","Detect","Dotsource")][string]$Action,
    [parameter(Mandatory=$true )][String]$PackageID, #Winget Package ID
    [parameter(Mandatory=$false)][String]$PackageVersion, #Winget Package Version
   #optional parameters for WinGet 
    [parameter(Mandatory=$false)][ValidateSet("machine", "user")][String]$InstallScope, # = "user",
    [parameter(Mandatory=$false)][String]$WingetSource = "winget",
    [parameter(Mandatory=$false)][String[]]$WingetParamsExtra
  )

#################################
### MAIN Function
### GETS EXPORTED

function main {

	$WinGetParamsCommon = "--source=$($WingetSource) --accept-source-agreements --disable-interactivity --exact"
	if ($WingetParamsExtra) { $WinGetParamsCommon +=          " $($WingetParamsExtra)"}

	$WinGetParamsInstallUninstall = "--silent"
	if ($InstallScope     ) { $WinGetParamsInstallUninstall += "--scope=$($InstallScope)"      }
	if ($PackageVersion   ) { $WinGetParamsInstallUninstall += " --version=$($PackageVersion)" }
 
	# WinGet Logs $($env:LOCALAPPDATA)\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir
	$Path_local = "$($Env:TEMP)\__IME" #our logs in %TEMP%
	$log_source = "WinGetWrapper"
	$log_output = "textlog" #this can be either textlog or eventlog (eventlog requires admin)
	$log_logname = "Application" #this is for Windows Eventlog


	### MAIN part 
    #Push-Location -Path $PSScriptRoot
	eventlog_init
	log_msg "STARTING"

	log_msg "Resolving Winget"
	$winget_exe = get_winget # resolve winget_exe
	log_msg "Resolving Winget: Result: [$winget_exe]"

	#exit $(Invoke-Expression "do_$($Action)")

	
#	if (Test-Path -LiteralPath "function:do_$($Action)") {
	$res = $(Invoke-Expression "do_$($Action)")
<#
	}
	else {
		log_msg -LogSeverity Error -LogMSG "Invalid action called [$Action], valid actions are:"
		foreach ($r in Get-Item -Path "function:do_*") { log_msg -LogSeverity Error -LogMSG "  $r"}
		$res = -1
	}
#>
	log_msg "END RESULT: [$($res[-1])]" #in case multiple outputs are produced, we want to see only the code
	eventlog_stop
	exit ($res[-1]) 
} #end of MAIN function

#############################
### DETECT if the app is installed
### MUST return 0 on success (for exit code)
### Runs PRE and POST install
### PRE detected -> app already installed, skip
### POST NOT detected -> app install failed, revert/retry
#############################

function do_detect {
    
if (!($PackageID)) { log_msg -LogSeverity Error -LogMSG "No AppID"; return 3} #no AppID
$result = &$winget_exe list --id $PackageID ($WinGetParamsCommon.Split(' '))
log_msg $result

if (-not ($result -like "*$PackageID*")) { log_msg -LogSeverity Error -LogMSG "Winget did not find the app"; return 1}
if ($PackageVersion) { # additional version check

    #winget loves to drop empty lines and progress bars at the beginning of the output, we only need the last few lines
    [Array]$scrubbedOutput = @($result[-3],$result[-1])
    
    #$result -notmatch "^[ -]" #remove empty lines (variable number, WRF winget?) and the ----.
	log_msg "[$($scrubbedOutput[0])] "
	
    # sanity check. Also generates $Matches
    $verPosStart = $scrubbedOutput[0].IndexOf("Version") 
    if ($verPosStart -le 0 ) { log_msg -LogSeverity Error -LogMSG "Winget failed to return proper version header [$($scrubbedOutput[0])]"; return 2 }

	# Determine the width of the field, between "Version" and the next word in header (word can differ: Available, Source, or there may be none)
    # I hate text parsing with variable command output format...
    $verPosEnd   = $scrubbedOutput[0].Substring($verPosStart+1) -cmatch "[A-Z]" #also generates the $Matches

    if ($verPosEnd -eq $false) { #this means that the Version is last in the line.
        $verPosEnd = $scrubbedOutput[1].Length #no next field = end of the line And yes, we need the other line, since the training spaces are auto-trimmed.
    # I hate text parsing with variable command output format...
    } else { $verPosEnd = $scrubbedOutput[0].IndexOf($Matches[0]) }

    log_msg "Version start-end: [$verPosStart | $verPosEnd]"
    $ver = $scrubbedOutput[1].Substring($verPosStart,$verPosEnd - $verPosStart).Trim() #cut out the version number from the second line
	log_msg "Version: [$ver]"
	if ($ver -ne $PackageVersion) { log_msg -LogSeverity Error -LogMSG "Winget returned version [$($ver)] that does not match required [$($PackageVersion)]"; return 2}

}
Write-Output "Detection of [$($PackageID)] version [$($ver)] ended succesfully."
return 0

}


#############################
### INSTALL
function do_install {

	$res =  &$winget_exe install --id $PackageID --accept-package-agreements ($WingetParamsCommon+" "+$WinGetParamsInstallUninstall).Split(' ')
    if ($lastexitcode -ne 0) { log_msg -LogSeverity Error -LogMSG "Fail with exitcode [$lastexitcode]. Details: [$res]"; return $lastexitcode }
		
    log_msg -LogMSG "Success"
    return 0 
}

#############################
### UNINSTALL

function do_uninstall {

    $res = &$winget_exe uninstall --id=$PackageID ($WingetParamsCommon+" "+$WinGetParamsInstallUninstall).Split(' ') 
    if ($lastexitcode -ne 0) { log_msg -LogSeverity Error -LogMSG "Fail with exitcode [$lastexitcode]. Details: [$res]"; return $lastexitcode }
		
    log_msg -LogMSG "Success"
    return 0 
}
###################################
###################################
#### HELPERS
###################################
###################################
function do_Dotsource { 
Write-Error "this should never be seen"
return 0 
} # this is only needed for dotsourcing

function eventlog_init {
    
    # if ([System.Diagnostics.EventLog]::SourceExists($log_source) -eq $false) 
    
    try {[System.Diagnostics.EventLog]::CreateEventSource($log_source,$log_logname)} 
    catch { # we lack admin rights and cannot write to event log
        $log_output = "textlog"
        Start-Transcript -Path "$Path_local\Log\$PackageID-$Action.log" -Force -Append
        $VerbosePreference = "continue"
    }
}

function eventlog_stop {
    $VerbosePreference = $oldVerbosePreference
    Stop-Transcript
}

function log_msg {
    param (
	    [string]$LogMSG = "[$log_source]: Logging attempt without a log message",
	    [string]$LogAction = $Action,
	    [ValidateSet("Error", "Information", "Warning")][string]$LogSeverity = "Information"
    )

    $log_prefix = "$log_source : $PackageID : $LogAction : "
	
	$log_params = @{
	  LogName = $log_logname
	  Source = $log_source
	  EventId = 9999
	  EntryType = $LogSeverity
	  Message = "$log_prefix $LogMSG"
	}
	
    if ($log_output -eq "eventlog") { Write-EventLog @log_params} 
	else {
		if ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Verbose $log_params.Message }
		else { Write-Host $log_params.Message }
	}                                                              
	
}

function get_winget {    #resolve winget depending on user/system context
    $winget = $null

    $DesktopAppInstaller = "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    $SystemContext = Resolve-Path "$DesktopAppInstaller" 
    #Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" | Select -Last 1 #in case there is more than one
    if ($SystemContext) { $SystemContext = $SystemContext[-1].Path }

    $UserContext = Get-Command winget.exe -ErrorAction SilentlyContinue

    log_msg " SystemContext [$SystemContext]"
    log_msg " UserContext [$UserContext]"
    if ($UserContext) { $winget = $UserContext.Source }
    elseif (Test-Path "$SystemContext\AppInstallerCLI.exe") { $winget = "$SystemContext\AppInstallerCLI.exe" }
    elseif (Test-Path "$SystemContext\winget.exe") { $winget = "$SystemContext\winget.exe" }
    
    if (!$winget) {log_msg -LogSeverity Error -LogMSG "WinGet not found"; return -1}
    return $winget
}

### BEHOLD THE PROGRAM ENTRY POINT 
If ($MyInvocation.InvocationName -ne ".") { main }
### wrapper for dot-souring in the winget_tool.ps1
### END