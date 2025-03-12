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
    Array of specific owner identifiers (DisplayName, UPN, or partial match) to filter App Registrations. If not provided, all App Registrations will be checked.

.EXAMPLE
    .\Check-AppRegistrationSecretExpiry.ps1
    Checks all App Registrations and exports the report to the default location.

.EXAMPLE
    .\Check-AppRegistrationSecretExpiry.ps1 -OutputPath "C:\Reports\ExpiringSecrets.csv" -DaysToExpiration 30
    Checks all App Registrations with a 30-day expiration threshold and exports to specified location.

.EXAMPLE
    .\Check-AppRegistrationSecretExpiry.ps1 -SpecificOwners @("John Doe", "jane@contoso.com")
    Checks only App Registrations owned by the specified user names or emails.
#>

param (
    [string]$OutputPath = "AppRegistrationsWithExpiringSecrets.csv",
    [int]$DaysToExpiration = 315,
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
        # Check if already connected to Azure
        $context = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Host "Not connected to Azure. Please connect using Connect-AzAccount first."
            throw "Not connected to Azure"
        }
        
        # Connect to Microsoft Graph
        $graphToken = (Get-AzAccessToken -Resource "https://graph.microsoft.com").Token | ConvertTo-SecureString -AsPlainText -Force
        Connect-MgGraph -AccessToken $graphToken -ErrorAction Stop
        Write-Host "Successfully connected to Microsoft Graph API"
    }
    catch {
        Write-Error "Failed to authenticate to Azure or Microsoft Graph: $_"
        throw
    }
}

# Function to get App Registrations based on filter criteria
function Get-FilteredAppRegistrations {
    param (
        [string[]]$OwnerIdentifiers
    )
    
    try {
        $allApps = Get-MgApplication -All
        Write-Host "Retrieved $($allApps.Count) total App Registrations"
        
        # Only apply filtering if we have valid owners
        $validOwners = $OwnerIdentifiers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        
        if ($validOwners.Count -gt 0) {
            Write-Host "Filtering App Registrations by $($validOwners.Count) specific owners..."
            
            # Create debugging summary of all search terms
            Write-Host "Owner search terms:" -ForegroundColor Cyan
            foreach ($owner in $validOwners) {
                Write-Host "  - [$owner]" -ForegroundColor Cyan
            }
            
            $filteredApps = @()
            $appWithOwnersCount = 0
            $matchedAppsCount = 0
            
            foreach ($app in $allApps) {
                $appOwners = Get-MgApplicationOwner -ApplicationId $app.Id
                
                # Debug information for every app
                Write-Verbose "Checking app: $($app.DisplayName) (ID: $($app.Id))"
                
                if ($appOwners -and $appOwners.Count -gt 0) {
                    $appWithOwnersCount++
                    $isMatch = $false
                    
                    # For debugging, explicitly identify all owners of the app
                    $allOwnerInfo = @()
                    
                    foreach ($owner in $appOwners) {
                        # Extract all possible owner identifiers
                        $ownerIdentifiers = @()
                        
                        if ($owner.AdditionalProperties.displayName) {
                            $ownerIdentifiers += $owner.AdditionalProperties.displayName
                        }
                        
                        if ($owner.AdditionalProperties.userPrincipalName) {
                            $ownerIdentifiers += $owner.AdditionalProperties.userPrincipalName
                        }
                        
                        if ($owner.AdditionalProperties.mail) {
                            $ownerIdentifiers += $owner.AdditionalProperties.mail
                        }
                        
                        # Add ID as fallback
                        $ownerIdentifiers += $owner.Id
                        
                        # Collect all owner info for this app
                        $ownerSummary = $ownerIdentifiers -join " / "
                        $allOwnerInfo += $ownerSummary
                        
                        # Debug output for each owner
                        Write-Verbose "  Owner identifiers: $ownerSummary"
                        
                        # Check for full or partial match against any owner identifier
                        foreach ($searchOwner in $validOwners) {
                            foreach ($identifier in $ownerIdentifiers) {
                                # FIXED: Use standard PowerShell comparison operators with case sensitivity
                                $exactMatch = $identifier -ceq $searchOwner  # Case-sensitive equals
                                $containsMatch = $identifier -and ($identifier.IndexOf($searchOwner, [StringComparison]::Ordinal) -ge 0)  # Case-sensitive contains
                                
                                Write-Verbose "    Comparing: '${identifier}' with '${searchOwner}' - Exact: $exactMatch, Contains: $containsMatch"
                                
                                # Special debugging for the problematic app
                                if ($app.DisplayName -like "*Wnioski02*") {
                                    Write-Host "WNIOSKI02 APP - Comparing:" -ForegroundColor Yellow
                                    Write-Host "  Owner: '${identifier}'" -ForegroundColor Yellow
                                    Write-Host "  Search: '${searchOwner}'" -ForegroundColor Yellow
                                    Write-Host "  ExactMatch: $exactMatch" -ForegroundColor Yellow
                                    Write-Host "  ContainsMatch: $containsMatch" -ForegroundColor Yellow
                                }
                                
                                if ($exactMatch -or $containsMatch) {
                                    Write-Host "Match found! App: $($app.DisplayName), Owner: $identifier" -ForegroundColor Green
                                    $filteredApps += $app
                                    $isMatch = $true
                                    $matchedAppsCount++
                                    break
                                }
                            }
                            if ($isMatch) { break }
                        }
                    }
                    
                    # Additional debugging for the problematic app
                    if ($app.DisplayName -like "*Wnioski02*" -and -not $isMatch) {
                        Write-Host "NO MATCH: 'Wnioski02' app with owners: $($allOwnerInfo -join ' | ')" -ForegroundColor Red
                    }
                }
                else {
                    Write-Verbose "  No owners found for this app"
                }
            }
            
            Write-Host "##vso[task.logissue type=warning]Found $appWithOwnersCount apps with owners"
            Write-Host "##vso[task.logissue type=warning]Matched $matchedAppsCount apps with the specified owner filter"
            
            # Emergency debugging to check if the Wnioski02 app is in the filtered results
            $wnioskiApp = $filteredApps | Where-Object { $_.DisplayName -like "*Wnioski02*" }
            if ($wnioskiApp) {
                Write-Host "WARNING: Wnioski02 app is still in the filtered results!" -ForegroundColor Red
            }
            
            return $filteredApps
        }
        else {
            Write-Host "No valid owner identifiers provided. Processing all App Registrations..."
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
            $ownerDetails = @()
            
            if ($owner.AdditionalProperties.displayName) {
                $ownerDetails += "Name: $($owner.AdditionalProperties.displayName)"
            }
            
            if ($owner.AdditionalProperties.userPrincipalName) {
                $ownerDetails += "UPN: $($owner.AdditionalProperties.userPrincipalName)"
            }
            
            if ($owner.AdditionalProperties.mail) {
                $ownerDetails += "Email: $($owner.AdditionalProperties.mail)"
            }
            
            if ($ownerDetails.Count -eq 0) {
                $ownerDetails += "ID: $($owner.Id)"
            }
            
            $ownersList += ($ownerDetails -join "; ")
        }
        
        return $ownersList -join " | "
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

# Debug info - always output exactly what's being searched for
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host "SCRIPT CONFIGURATION:" -ForegroundColor Cyan
Write-Host "OutputPath: $OutputPath" -ForegroundColor Cyan
Write-Host "DaysToExpiration: $DaysToExpiration" -ForegroundColor Cyan
Write-Host "SpecificOwners:" -ForegroundColor Cyan
if ($SpecificOwners.Count -eq 0) {
    Write-Host "  EMPTY ARRAY - Will process ALL app registrations" -ForegroundColor Red
} else {
    foreach ($owner in $SpecificOwners) {
        $displayValue = if ([string]::IsNullOrWhiteSpace($owner)) { "<EMPTY STRING>" } else { "[$owner]" }
        Write-Host "  - $displayValue" -ForegroundColor Cyan
    }
}
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan

# Install required modules
Install-Module Microsoft.Graph -AllowClobber -Force -Scope CurrentUser -ErrorAction SilentlyContinue
#Install-Module Microsoft.Graph.Beta -AllowClobber -Force

try {
    # Set verbose output
    $VerbosePreference = "Continue"
    
    # Ensure required modules are installed
    Ensure-ModulesInstalled
    
    # Ensure authenticated to Azure
    Ensure-AzureAuthentication
    
    # Get filtered app registrations
    $appRegistrations = Get-FilteredAppRegistrations -OwnerIdentifiers $SpecificOwners
    
    Write-Host "##vso[task.logissue type=warning]Found $($appRegistrations.Count) App Registrations to check for expiring credentials"
    
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
    
    # Export results to CSV and output VSO task logs for expired credentials
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Host "##vso[task.logissue type=warning]Found $expiringAppsCounter App Registrations with $($results.Count) expiring or expired credentials"
        Write-Host "Report exported to: $OutputPath"
        
        # Output VSO task logs for expired app registrations
        foreach ($result in $results) {
            if ($result.Status -eq "Expired") {
                $message = "Expired App Registration: $($result.DisplayName) - $($result.CredentialType) expired $([Math]::Abs($result.DaysToExpiration)) days ago"
                Write-Host "##vso[task.logissue type=error]$message"
            } 
            elseif ($result.Status -eq "Expiring") {
                $message = "Expiring App Registration: $($result.DisplayName) - $($result.CredentialType) expires in $($result.DaysToExpiration) days"
                Write-Host "##vso[task.logissue type=warning]$message"
            }
        }
    }
    else {
        Write-Host "##vso[task.logissue type=warning]No App Registrations found with credentials expiring within $DaysToExpiration days"
    }
    
    # Only display troubleshooting information if explicitly requested
    if ($appRegistrations.Count -eq 0 -and $false) {  # Set to $true if you want to see the troubleshooting info
        Write-Host "For troubleshooting purposes, listing some app registrations and their owners:"
        $sampleApps = Get-MgApplication -Top 10
        foreach ($app in $sampleApps) {
            Write-Host "App: $($app.DisplayName)" -ForegroundColor Yellow
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id
            if ($owners) {
                foreach ($owner in $owners) {
                    Write-Host "  Owner DisplayName: $($owner.AdditionalProperties.displayName)"
                    Write-Host "  Owner UPN: $($owner.AdditionalProperties.userPrincipalName)"
                    Write-Host "  Owner Mail: $($owner.AdditionalProperties.mail)"
                    Write-Host "  Owner ID: $($owner.Id)"
                    Write-Host "  ---"
                }
            } else {
                Write-Host "  No owners found"
            }
            Write-Host ""
        }
    }
}
catch {
    Write-Error "Error in main script execution: $_"
}
