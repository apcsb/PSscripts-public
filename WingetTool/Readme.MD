# WinGet Tool and Wrapper
USE AS IS. I BEAR NO RESPONSIBILITY - IT IS ALL YOUR PROBLEM, INCLUDING ALL RISKS RELATED TO PUBLIC WINGET REPO. 

A wrapper for deploying apps via WinGet public repository and a tool to automatically create the apps in Intune

**winget_wrapper.ps1** - wrapper that does the on-device [un]installation / detection
Understands Package ID, Version, Action

**winget_tool.ps1** - tool to create apps in Intune. Understands lots of parameters
Automatically creates IntuneWin files, check scripts etc. By default assigns the app to all users as Available (can be turned off). Relies on tons of defaults and other things listed in **Important Notes or nothing will work** - check it out (one-time setup).

### USAGE EXAMPLE for CMD
*^ is the newline escape for multiline commands, you don't need it if putting everything on a single line*

	Powershell.exe ^
		-File winget_tool.ps1 ^
		-Action UploadWin32App  ^
		-PackageID 7zip.7zip ^

Some important parameters for package creation:
* **-PackageVersion 22.01**

*if not specified, will pull and check against the latest version*
* **-DisplayName "7Zip (WinGet_Tool)"**

*Mandatory for creating an app. If not specified, will be pulled from manifest or will contain PackageID*
* **-Description "Demo of a WinGet Win32 upload PS1 script"**

*Mandatory for creating an app. If not specified, will be pulled from manifest or will contain PackageID*
* **-Publisher "7ZIP"**

*Mandatory for creating an app. If not specified, will be pulled from manifest or will contain PackageID*

* **-IconFile "7zip.png"**

*If not specified, will look for **$($PackageID)_Icon.\*** or there will be no icon*

Other actions are listed in the PS1 file (Install, Uninstall, Detect, GenerateCheck). I will write embedded help into the PS1 file in due time. In the meanwhile, check the parameter section of the script.

## Important notes
* Requires the [IntuneWin32App module](https://github.com/MSEndpointMgr/IntuneWin32App) (*will be downloaded and installed automatically, if missing*)
* Since the script works silently, it requires an App Registration in AAD with permission **DeviceManagementApps.ReadWrite.All** 
	* make sure to grant it to your app
	* modify the **$AAD_ClientID** and **$AAD_TenantID** as well in the script, so that you don't have to specify them every time
* The script can connect using a Certificate or Shared Secret. Shared secrets are bad, mkay? Add a cert to your app registration *(self-signed works just fine)* and modify the  **AAD_ClientCertName** or **AAD_ClientCertThumb** with the Subject or Thumbprint of your cert respectively
* The silent automated install checks in Intune require the check scripts to be signed. Provide the default Subject of your Code Signing Cert in the **$CertSubject** parameter. See the section on Signing certs below
* **WinGet was initially designed for User Context only** - not every package will install in System Context. Test the installation under the System Context manually (PSexec etc.) and see if it works. Change the context via **$InstallScope** parameter if necessary.
* **Check other parameters and defaults** - there is a lot of them, and I haven't had time to write proper help yet.

## Signing Certs (crash course)
Read here how to create a code signing cert and install it onto your machine: https://adamtheautomator.com/how-to-sign-powershell-script/

Read here's how to import the cert into Intune's Trusted Publishers store

*(!You will also need to deploy it as a trusted root, or build a proper chain, but your Published cert must be achored at root - you will need to deploy both certs)*
https://techcommunity.microsoft.com/t5/intune-customer-success/adding-a-certificate-to-trusted-publishers-using-microsoft/ba-p/1974488

This will be handy:

OMA DM URI
>./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/<CERT_THUMBPRINT>/EncodedCertificate

Cert as Base64 with line breaks (PowerShell)
> [System.Convert]::ToBase64String((Get-Item -Path Cert:\LocalMachine\My\$Cert_Thumbprint).RawData, 'InsertLineBreaks')

Cert as Base64 w/o line breaks (PowerShell)
> [System.Convert]::ToBase64String((Get-Item -Path Cert:\LocalMachine\My\$Cert_Thumbprint).RawData)

Export Cert (PowerShell) for Intune Profile as Base64 with line breaks
 >[System.Convert]::ToBase64String(([System.Security.Cryptography.X509Certificates.X509Certificate2]::new("<path_to_certificate>")).Export('Cert'), 'InsertLineBreaks')​

## TODO
* Automated creation and deployment of signing cert and respective profile
* Help
* Optimizations, cleanup, rename parameters in a uniform way
* More error handling (maybe)
* More explicit support for upgrades and downgrades (currently WinGet install handles it, if the version if newer)
* Update existing IntuneApp