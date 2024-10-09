#Requres -Modules {ModuleName='Microsoft.PowerShell.TextUtility'}

#this CMDlet will take a string as an input, pass it to WinGet.exe
#it will then take the output, remove all lines until the line before '-----*' and use ConvertFrom-TextTable to convert the output to a PScustomobject, which will be returned

function Get-WinGet {
    param(
        [string]$params
    )
    <#
    #check if the module Microsoft.PowerShell.TextUtility is installed
    #ensure no output is generated
    if (-not(Get-Module -Name Microsoft.PowerShell.TextUtility)) {
        Install-Module -Name Microsoft.PowerShell.TextUtility -Force
    }
    #>
    
    #Call WinGet.exe with the given parameters
    $output = WinGet.exe $params
    
    #find how many lines are in the output
    $lineNumber = $output.IndexOf($output -match '----+') - 2
    #$lineNumber = ($output | Select-String '----+' | Select-Object -First 1 | ForEach-Object { $_.LineNumber }) -2

    #if the output is empty, return $null
    if ($lineNumber -lt 0) { return $null}

    #remove all the lines before $lineNumber
    #$output = $output[$lineNumber..($output.Length-1)] | ConvertFrom-TextTable

    #$output = $output[$lineNumber..($output.Length-1)]
    #$output = $output | ConvertFrom-TextTable
    return $output[$lineNumber..($output.Length-1)] | ConvertFrom-TextTable
}
