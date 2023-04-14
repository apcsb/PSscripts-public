#usage 
#powershell.exe -File EPMhelper.ps1 -Verbose -InFile <file.exe> [-OutFile <file.cer>]
[cmdletbinding()]
param (
	[Parameter(Mandatory=$true,  Position=0)][string] $InFile,
	[Parameter(Mandatory=$false, Position=1)][string] $OutFile = $InFile+".cer"
	)

Write-Verbose "InFile = [$($InFile)]"
if (!$InFile -or !(Test-Path $InFile -PathType Leaf)) {
	Write-Error "File Path [$($InFile)] not found. Exiting..."
	Exit -1
} 
Write-Verbose "OutFile = [$($OutFile)]"

#get file hash of the InFile
Write-Verbose "File Hash       = [$((Get-FileHash $InFile).Hash)]"

#Get-AuthenticodeSignature -FilePath $InFile | Select-Object -ExpandProperty SignerCertificate | Export-Certificate -Type CERT -FilePath $OutFile
$sign = Get-AuthenticodeSignature -FilePath $InFile
if ((!$sign) -or (!$sign.SignerCertificate)) {
	Write-Error "Issue with the signature [$($sign)] [$($sign.SignerCertificate)]. Exiting..."
	Exit -2
}
Write-Verbose "Cert Subject    = [$($sign.SignerCertificate.Subject)]"
Write-Verbose "Cert Thumbprint = [$($sign.SignerCertificate.Thumbprint)]"


Export-Certificate -Cert $sign.SignerCertificate -Type CERT -FilePath $OutFile
Exit $LASTEXITCODE
