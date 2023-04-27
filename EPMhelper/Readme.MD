# Intune Endpoint Privilege Management Signing Cert Helper
USE AS IS. I BEAR NO RESPONSIBILITY - IT IS ALL YOUR PROBLEM.

In the current state (check Readme date) of Intune's Endpoint Privilege Management, if you want to use the elevation rules based on the executable's signing certificate, you must extract this certificate from the file and manually upload it (along with providing some parameters).

This script will pull the signing certificate from the executable file for you, as well as provide some useful info that you might need while filling out the rules.

#### Usage
>EPMhelper.ps1 -InFile *<exe_file.exe>* [-OutFile *<certificate_file.cer>*]

#### Detailed parameter description

>[Parameter(Mandatory=$true,  Position=0)][string] **$InFile**,  
>[Parameter(Mandatory=$false, Position=1)][string] **$OutFile** = $InFile+".cer"

Enjoy!