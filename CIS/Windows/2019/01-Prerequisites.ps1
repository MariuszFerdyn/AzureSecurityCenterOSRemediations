# Install DSC Modules for Windows Server 2019 CIS Benchmark

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges. Please run PowerShell as administrator and try again."
    exit
}

Write-Host "Checking and installing required PowerShell modules..." -ForegroundColor Yellow

# Check and install NuGet provider if needed (required for PowerShellGet)
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "Installing NuGet package provider..." -ForegroundColor Cyan
    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
}

# Set PSGallery as trusted
if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Write-Host "Setting PSGallery as a trusted repository..." -ForegroundColor Cyan
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

# List of required modules
$requiredModules = @(
    "AuditPolicyDsc",
    "SecurityPolicyDsc",
    "NetworkingDsc"
)

# Install each module if not already installed
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module $module..." -ForegroundColor Cyan
        try {
            Install-Module -Name $module -Force -Scope AllUsers
            Write-Host "Module $module installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install module $module. Error: $_"
        }
    }
    else {
        Write-Host "Module $module is already installed." -ForegroundColor Green
    }
}

# Verify all modules are installed
$missingModules = @()
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Error "The following modules could not be installed: $($missingModules -join ', ')"
} else {
    Write-Host "All required modules are installed successfully." -ForegroundColor Green
    Write-Host "You can now run your CIS Benchmark script." -ForegroundColor Green
}
