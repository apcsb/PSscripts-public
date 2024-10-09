<#
This script will do the following (using 
https://learn.microsoft.com/en-us/windows-365/enterprise/place-cloud-pc-under-review#set-up-your-azure-storage-account
)

0. Connect to Azure  either by prompting user for credentials, or (TBD) by using a service principal and a stored certificate (must be provided as parameters)
    Optionally, a subscription ID can be provided as a parameter, if the account has multiple subscriptions
1. Check is a storage account with the name $W365SAccName exists in the resource group $W365SAccRG. 
2. If not, create it (and the resource group if necessary), using the following parameters (taken from the doc above)
    
    Region: $W365SAccRGLocation
    Performance: Premium
    Premium account type: Page blobs
    Minimum TLS version: Version 1.2
    Network access: Enable public access from all networks


3. Assign the following roles on this Storage Account to the Windows 365 Service Principal
    * Storage Blob Data Contributor 
    * Storage Account Contributor

    In order to do this, the script will look for Enterprise Application named "Windows 365"

4. Return a PScustomObject containing the following parameters of the found/created storage account:
    * Name
    * Resource Group
    * Location
    * ID
    * ConnectionString

The script will be using Azure PowerShell Az module.
#>

param(
    
    [string]$W365SAccName = "w365underreview", #lowecase letters and numbers only, globally unique
    [string]$W365SAccRG = "VDI-W365",
    [string]$W365SAccRGLocation = "Germany West Central",
    [string]$AzSubId = "" #add yours here if you have many subs or supply as a parameter
)

### CONSTANTS ###
$W365ServicePrincipalName = "Windows 365" #don't change this, should work as is

### SCRIPT STARTS HERE ###
#connect to Azure (interactive)
Connect-AzAccount

#set the subscription, if the parameter is provided
if ($AzSubId) { Set-AzContext -SubscriptionId $AzSubId }

#check if the Resource Group exists
$resourceGroup = Get-AzResourceGroup -Name $W365SAccRG -ErrorAction SilentlyContinue

# if it doesn't exist, create it
if (-not $resourceGroup) { $resourceGroup = New-AzResourceGroup -Name $W365SAccRG -Location $W365SAccRGLocation }

#check if the storage account exists
$storageAccount = Get-AzStorageAccount -Name $W365SAccName -ResourceGroupName $W365SAccRG -ErrorAction SilentlyContinue

# if it doesn't exist, create it
if (-not $storageAccount) {
    $storageAccountParams = @{
        StorageAccountName    = $W365SAccName
        ResourceGroupName     = $W365SAccRG
        SkuName               = "Premium_LRS"
        Kind                  = "StorageV2"
        Location              = $W365SAccRGLocation
        MinimumTlsVersion     = "TLS1_2"
        EnableHttpsTrafficOnly= $true
        AllowBlobPublicAccess = $true
    }

    $storageAccount = New-AzStorageAccount @storageAccountParams
}

# get the service principal
$servicePrincipal = Get-AzADServicePrincipal -DisplayName $W365ServicePrincipalName
if (-not $servicePrincipal) {
    Write-Host "Service Principal not found"
    exit
}

# assign the roles
New-AzRoleAssignment -ObjectId $servicePrincipal.Id -RoleDefinitionName "Storage Blob Data Contributor" -Scope $storageAccount.Id
New-AzRoleAssignment -ObjectId $servicePrincipal.Id -RoleDefinitionName "Storage Account Contributor" -Scope $storageAccount.Id

# return the storage account
[PSCustomObject]@{
    Name = $storageAccount.StorageAccountName
    ResourceGroup = $storageAccount.ResourceGroupName
    Location = $storageAccount.Location
    ID = $storageAccount.Id
    ConnectionString = (Get-AzStorageAccountKey -ResourceGroupName $W365SAccRG -Name $W365SAccName).ConnectionString
}

#disconnect from Azure
Disconnect-AzAccount

### THE END ###
Write-Host "Finished"