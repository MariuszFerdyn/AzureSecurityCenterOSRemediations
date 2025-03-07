#Connect-AzAccount
#Connect-AzureAD
#
<#
.SYNOPSIS
    Checks Azure App Registrations for secrets and certificates that are expiring in 15 days or less or have already expired.

.DESCRIPTION
    This script identifies all Azure App Registrations with secrets or certificates that are expiring soon (within 15 days) 
    or have already expired. It can filter based on specific owners or check all service principals.
    The results are exported to a CSV file with detailed application information.

.PARAMETER OutputPath
    Path where the CSV report will be saved. Default is "AppRegistrationsWithExpiringSecrets.csv" in the current directory.

.PARAMETER DaysToExpiration
    Number of days threshold for expiration check. Default is 15 days.

.PARAMETER SpecificOwners
    Array of specific owner names (DisplayName) to filter App Registrations. If not provided, all App Registrations will be checked.

.EXAMPLE
    .\Check-AppRegistrationSecretExpiry.ps1
    Checks all App Registrations and exports the report to the default location.

.EXAMPLE
    .\Check-AppRegistrationSecretExpiry.ps1 -OutputPath "C:\Reports\ExpiringSecrets.csv" -DaysToExpiration 30
    Checks all App Registrations with a 30-day expiration threshold and exports to specified location.

.EXAMPLE
    .\Check-AppRegistrationSecretExpiry.ps1 -SpecificOwners @("John Doe", "Jane Smith")
    Checks only App Registrations owned by the specified user names.
#>

param (
    [string]$OutputPath = "AppRegistrationsWithExpiringSecrets.csv",
    [int]$DaysToExpiration = 15,
    [string[]]$SpecificOwners = @()
)

# Function to check if required modules are installed and install if missing
function Ensure-ModulesInstalled {
    $requiredModules = @("Az.Accounts", "Az.Resources", "Microsoft.Graph.Applications")
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Module $module is not installed. Installing..."
            Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
        }
    }
    
    # Load the modules
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    Import-Module Microsoft.Graph.Applications -ErrorAction Stop
}

# Function to ensure authenticated to Azure
function Ensure-AzureAuthentication {
    try {
        # Check Az authentication
        $azContext = Get-AzContext
        if (-not $azContext) {
            Write-Host "Not authenticated to Azure. Initiating Az login..."
            Connect-AzAccount
        }
        else {
            Write-Host "Already authenticated to Azure as $($azContext.Account) in subscription $($azContext.Subscription.Name)"
        }
        
        # Connect to Microsoft Graph
        Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All"
    }
    catch {
        Write-Host "Error checking Azure authentication: $_"
        Write-Host "Initiating logins..."
        Connect-AzAccount
        Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All"
    }
}

# Function to get App Registrations based on filter criteria
function Get-FilteredAppRegistrations {
    param (
        [string[]]$OwnerNames
    )
    
    try {
        $allApps = Get-MgApplication -All
        
        if ($OwnerNames.Count -gt 0) {
            Write-Host "Filtering App Registrations by specific owners (by name)..."
            $filteredApps = @()
            
            foreach ($app in $allApps) {
                $appOwners = Get-MgApplicationOwner -ApplicationId $app.Id
                foreach ($owner in $appOwners) {
                    if ($owner.AdditionalProperties.displayName) {
                        $ownerDisplayName = $owner.AdditionalProperties.displayName
                    }
                    elseif ($owner.AdditionalProperties.userPrincipalName) {
                        $ownerDisplayName = $owner.AdditionalProperties.userPrincipalName
                    }
                    else {
                        $ownerDisplayName = ""
                    }
                    
                    # Check if the owner's display name matches any in the provided list
                    if ($OwnerNames -contains $ownerDisplayName) {
                        $filteredApps += $app
                        break
                    }
                }
            }
            
            return $filteredApps
        }
        else {
            Write-Host "Processing all App Registrations..."
            return $allApps
        }
    }
    catch {
        Write-Error "Error retrieving App Registrations: $_"
        return @()
    }
}

# Function to get and format application owners
function Get-FormattedAppOwners {
    param (
        [string]$AppId
    )
    
    try {
        $owners = Get-MgApplicationOwner -ApplicationId $AppId -ErrorAction SilentlyContinue
        if (-not $owners -or $owners.Count -eq 0) {
            return "No owners"
        }
        
        $ownersList = @()
        
        foreach ($owner in $owners) {
            if ($owner.AdditionalProperties.displayName) {
                $ownerDisplayName = $owner.AdditionalProperties.displayName
            }
            elseif ($owner.AdditionalProperties.userPrincipalName) {
                $ownerDisplayName = $owner.AdditionalProperties.userPrincipalName
            }
            else {
                $ownerDisplayName = $owner.Id
            }
            
            $ownersList += $ownerDisplayName
        }
        
        return $ownersList -join "|"
    }
    catch {
        Write-Warning "Error retrieving owners for application $AppId`: $($_.Exception.Message)"
        return "Error retrieving owners"
    }
}

# Function to check if a secret or certificate is expiring soon
function Is-ExpiringOrExpired {
    param (
        [datetime]$EndDate,
        [int]$DaysThreshold
    )
    
    $timeUntilExpiration = $EndDate - (Get-Date)
    return $timeUntilExpiration.TotalDays -le $DaysThreshold
}

# Function to get expiring secrets and certificates for an app
function Get-ExpiringSecrets {
    param (
        [Microsoft.Graph.PowerShell.Models.MicrosoftGraphApplication]$App,
        [int]$DaysThreshold
    )
    
    $expiringCredentials = @()
    
    # Get password credentials (secrets)
    if ($App.PasswordCredentials) {
        foreach ($credential in $App.PasswordCredentials) {
            if ($credential.EndDateTime -and (Is-ExpiringOrExpired -EndDate $credential.EndDateTime -DaysThreshold $DaysThreshold)) {
                $expiringCredentials += @{
                    Type = "Secret"
                    KeyId = $credential.KeyId
                    DisplayName = $credential.DisplayName
                    EndDate = $credential.EndDateTime
                    DaysToExpiration = [math]::Round(($credential.EndDateTime - (Get-Date)).TotalDays, 1)
                    Status = if (($credential.EndDateTime - (Get-Date)).TotalDays -lt 0) { "Expired" } else { "Expiring" }
                }
            }
        }
    }
    
    # Get certificate credentials
    if ($App.KeyCredentials) {
        foreach ($credential in $App.KeyCredentials) {
            if ($credential.EndDateTime -and (Is-ExpiringOrExpired -EndDate $credential.EndDateTime -DaysThreshold $DaysThreshold)) {
                $expiringCredentials += @{
                    Type = "Certificate"
                    KeyId = $credential.KeyId
                    DisplayName = $credential.DisplayName
                    EndDate = $credential.EndDateTime
                    DaysToExpiration = [math]::Round(($credential.EndDateTime - (Get-Date)).TotalDays, 1)
                    Status = if (($credential.EndDateTime - (Get-Date)).TotalDays -lt 0) { "Expired" } else { "Expiring" }
                }
            }
        }
    }
    
    return $expiringCredentials
}

# Function to get required resource access details in readable format
function Get-FormattedRequiredResourceAccess {
    param (
        [object[]]$RequiredResourceAccess
    )
    
    if (-not $RequiredResourceAccess -or $RequiredResourceAccess.Count -eq 0) {
        return ""
    }
    
    $result = @()
    foreach ($resource in $RequiredResourceAccess) {
        $apiDetails = ""
        try {
            # Try to get friendly name for the resource
            $resourceAppId = $resource.ResourceAppId
            $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$resourceAppId'" -ErrorAction SilentlyContinue
            $resourceName = if ($servicePrincipal) { $servicePrincipal.DisplayName } else { $resourceAppId }
            
            # Get permissions
            $permissions = @()
            foreach ($permission in $resource.ResourceAccess) {
                $permissions += "$($permission.Id):$($permission.Type)"
            }
            
            $apiDetails = "$resourceName;$($permissions -join ',')"
        }
        catch {
            $apiDetails = "$($resource.ResourceAppId);Unknown permissions"
        }
        
        $result += $apiDetails
    }
    
    return $result -join "|"
}

# Function to format redirect URIs
function Format-RedirectUris {
    param (
        [string[]]$UriList
    )
    
    if (-not $UriList -or $UriList.Count -eq 0) {
        return ""
    }
    
    return $UriList -join "|"
}

# Main script execution
try {
    # Ensure required modules are installed
    Ensure-ModulesInstalled
    
    # Ensure authenticated to Azure
    Ensure-AzureAuthentication
    
    # Get filtered app registrations
    $appRegistrations = Get-FilteredAppRegistrations -OwnerNames $SpecificOwners
    
    Write-Host "Found $($appRegistrations.Count) App Registrations to check"
    
    $results = @()
    $appCounter = 0
    $expiringAppsCounter = 0
    
    foreach ($app in $appRegistrations) {
        $appCounter++
        Write-Progress -Activity "Checking App Registrations" -Status "Processing $appCounter of $($appRegistrations.Count)" -PercentComplete (($appCounter / $appRegistrations.Count) * 100)
        
        $expiringCredentials = Get-ExpiringSecrets -App $app -DaysThreshold $DaysToExpiration
        
        if ($expiringCredentials.Count -gt 0) {
            $expiringAppsCounter++
            
            foreach ($credential in $expiringCredentials) {
                # Handle redirectURIs appropriately based on the structure
                $redirectUris = @()
                if ($app.Web -and $app.Web.RedirectUris) {
                    $redirectUris = $app.Web.RedirectUris
                }
                
                # Handle identifierUris
                $identifierUris = if ($app.IdentifierUris) { $app.IdentifierUris -join "|" } else { "" }
                
                # Get owners for this application
                $owners = Get-FormattedAppOwners -AppId $app.Id
                
                $result = [PSCustomObject]@{
                    DisplayName = $app.DisplayName
                    Description = $app.Description
                    AppId = $app.AppId
                    SignInAudience = $app.SignInAudience
                    DeletedDateTime = $app.DeletedDateTime
                    ApplicationTemplateId = $app.ApplicationTemplateId
                    CreatedDateTime = $app.CreatedDateTime
                    IdentifierUris = $identifierUris
                    IsDeviceOnlyAuthSupported = $app.IsDeviceOnlyAuthSupported
                    IsFallbackPublicClient = $app.IsFallbackPublicClient
                    PublisherDomain = $app.PublisherDomain
                    ServiceManagementReference = $app.ServiceManagementReference
                    RedirectUris = Format-RedirectUris -UriList $redirectUris
                    RequiredResourceAccess = Get-FormattedRequiredResourceAccess -RequiredResourceAccess $app.RequiredResourceAccess
                    Owners = $owners
                    CredentialType = $credential.Type
                    CredentialKeyId = $credential.KeyId
                    CredentialName = $credential.DisplayName
                    ExpirationDate = $credential.EndDate
                    DaysToExpiration = $credential.DaysToExpiration
                    Status = $credential.Status
                }
                
                $results += $result
            }
        }
    }
    
    # Export results to CSV
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Host "Found $expiringAppsCounter App Registrations with $($results.Count) expiring or expired credentials"
        Write-Host "Report exported to: $OutputPath"
    }
    else {
        Write-Host "No App Registrations found with credentials expiring within $DaysToExpiration days"
    }
}
catch {
    Write-Error "Error in main script execution: $_"
}
