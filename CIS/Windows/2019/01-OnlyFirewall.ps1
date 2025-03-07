<#
.SYNOPSIS
    DSC script to harden Windows Server 2019 firewall policies.
.DESCRIPTION
    This script configures Windows Server 2019 firewall settings using Desired State Configurations (DSC).
    Extracted from CIS Benchmark Windows Server 2019 Version 1.0.0 hardening script.
.NOTE
    Copyright (c) ZCSPM. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.EXAMPLE
    
    .\Windows_Server_2019_Firewall_Hardening.ps1 [Script will install required modules and then configure the firewall]
#>

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges. Please run PowerShell as administrator and try again."
    exit
}

# ====================== STEP 1: INSTALL AND IMPORT REQUIRED MODULES ======================

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
    "PSDesiredStateConfiguration",
    "AuditPolicyDsc",
    "SecurityPolicyDsc",
    "NetworkingDsc"
)

# Install each module if not already installed
foreach ($module in $requiredModules) {
    # Skip PSDesiredStateConfiguration as it's built-in
    if ($module -eq "PSDesiredStateConfiguration") {
        Write-Host "Module $module is built-in, skipping installation." -ForegroundColor Green
        continue
    }
    
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module $module..." -ForegroundColor Cyan
        try {
            # First try to install with AllUsers scope
            Install-Module -Name $module -Force -Scope AllUsers -ErrorAction Stop
            Write-Host "Module $module installed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Could not install $module with AllUsers scope. Trying CurrentUser scope..." -ForegroundColor Yellow
            try {
                # If AllUsers fails, try with CurrentUser scope
                Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction Stop
                Write-Host "Module $module installed successfully with CurrentUser scope." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install module $module. Error: $_"
            }
        }
    }
    else {
        Write-Host "Module $module is already installed." -ForegroundColor Green
    }
}

# Verify all modules are installed
$missingModules = @()
foreach ($module in $requiredModules) {
    # Skip the built-in PSDesiredStateConfiguration
    if ($module -eq "PSDesiredStateConfiguration") { continue }
    
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Error "The following modules could not be installed: $($missingModules -join ', ')"
    Write-Host "Running 'Start-DscConfiguration' may fail without these modules." -ForegroundColor Yellow
}
else {
    Write-Host "All required modules are installed successfully." -ForegroundColor Green
}

# ====================== STEP 2: CREATE THE CONFIGURATION ======================

# Save the MOF configuration to disk
$configurationsPath = Join-Path $env:TEMP "FirewallConfigurations"
if (-not (Test-Path $configurationsPath)) {
    New-Item -Path $configurationsPath -ItemType Directory -Force | Out-Null
}

# Create the configuration script file
$configScriptPath = Join-Path $configurationsPath "FirewallConfig.ps1"

# Here we create a separate configuration script that will be run in its own process
$configScript = @'
Configuration Windows_Server_2019_Firewall_Hardening {
    param (
        [string[]]$ComputerName = 'localhost'
    )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'
 
    Node $ComputerName {

        # Windows Firewall: Domain Profile

        # CceId: CCE-36062-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallDomain' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }
        
        # CceId: CCE-38041-0 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
        Registry 'OffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
            ValueName = 'OffNotifications'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-36146-9 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
        Registry 'OutboundActionDefault' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
            ValueName = 'OutboundActionDefault'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Windows Firewall: Private Profile
        
        # CceId: CCE-38239-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPrivate' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37621-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No''
        Registry 'DisableNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DisableNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37434-8 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
        Registry 'DefaultOutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'DefaultOutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
        Registry 'AllowLocalPolicyMerge' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueName = 'AllowLocalPolicyMerge'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # Windows Firewall: Public Profile
        
        # CceId: CCE-37862-0
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Registry 'EnableFirewallPublic' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'EnableFirewall'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37330-8
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
        Registry 'turuoffNotifications' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'turuoffNotifications'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-37434-8 
        # DataSource: Registry Policy
        # Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)
        Registry 'OutboundAction' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueName = 'OutboundAction'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # Additional firewall-related settings

        # CceId: CCE-37450-4 
        # DataSource: Registry Policy
        # Ensure 'Turn off multicast name resolution' is set to 'Enabled' 
        Registry 'EnableMulticast' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName = 'EnableMulticast'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: CCE-38002-2
        # DataSource: Registry Policy
        # Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'NC_AllowNetBridge_NLA' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_AllowNetBridge_NLA'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: NOT_ASSIGNED
        # Control no: AZ-WIN-00143
        # DataSource: Registry Policy
        # Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
        Registry 'NC_PersonalFirewallConfig' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
            ValueName = 'NC_PersonalFirewallConfig'
            ValueType = 'DWord'
            ValueData = '0'
        }

        # CceId: CCE-38338-0
        # DataSource: Registry Policy
        # Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
        Registry 'fMinimizeConnections' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName = 'fMinimizeConnections'
            ValueType = 'DWord'
            ValueData = '1'
        }

        # CceId: 
        # DataSource: Registry Policy
        # Ensure 'Enable insecure guest logons' is set to 'Disabled'
        Registry 'AllowInsecureGuestAuth' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
        }
    }
}

# Run the configuration to generate MOF files
Windows_Server_2019_Firewall_Hardening -OutputPath "$env:TEMP\FirewallConfigurations"
'@

# Write the configuration script to file
$configScript | Out-File -FilePath $configScriptPath -Force

# ====================== STEP 3: EXECUTE THE CONFIGURATION ======================

Write-Host "Generating DSC configuration MOF files..." -ForegroundColor Cyan

try {
    # Execute the configuration script in a new PowerShell process
    $mofPath = Join-Path $configurationsPath "localhost.mof"
    
    # Run the configuration script in a new PowerShell session
    $process = Start-Process -FilePath "powershell.exe" -ArgumentList "-File `"$configScriptPath`"" -Wait -PassThru -NoNewWindow
    
    # Check if MOF file was generated
    if ($process.ExitCode -eq 0 -and (Test-Path $mofPath)) {
        Write-Host "MOF file generated successfully at: $mofPath" -ForegroundColor Green
        
        # Ask user if they want to apply the configuration
        $applyConfig = Read-Host "Do you want to apply the firewall configuration? (YES/NO)"
        if ($applyConfig -eq "YES") {
            Write-Host "Applying DSC configuration..." -ForegroundColor Yellow
            
            # Apply the configuration
            Start-DscConfiguration -Path $configurationsPath -Force -Verbose -Wait
            
            # Check configuration status
            $status = Get-DscConfigurationStatus
            if ($status.Status -eq "Success") {
                Write-Host "Firewall configuration applied successfully!" -ForegroundColor Green
            } else {
                Write-Host "Firewall configuration completed with status: $($status.Status)" -ForegroundColor Yellow
                Write-Host "Check the detailed logs for any issues." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Configuration not applied. You can manually apply it later with:" -ForegroundColor Cyan
            Write-Host "Start-DscConfiguration -Path $configurationsPath -Force -Verbose -Wait" -ForegroundColor Yellow
        }
    } else {
        Write-Error "Failed to generate MOF file. Check for errors in the configuration script."
    }
} catch {
    Write-Error "Error executing configuration: $_"
}