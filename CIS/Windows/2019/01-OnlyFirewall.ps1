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
    # PREREQUISITE
    * Windows PowerShell version 5 and above
        1. To check PowerShell version type "$PSVersionTable.PSVersion" in PowerShell and you will find PowerShell version,
        2. To Install powershell follow link https://docs.microsoft.com/en-us/powershell/scripting/install/installing-windows-powershell?view=powershell-6
    * DSC modules should be installed
        1. NetworkingDsc
        2. PSDesiredStateConfiguration
        
        To check module installation type "Get-InstalledModule -Name <ModuleName>" in PowerShell window
        You can Install the required modules by executing below command.
            Install-Module -Name <ModuleName> -MinimumVersion <Version>
.EXAMPLE
    
    .\Windows_Server_2019_Firewall_Hardening.ps1 [Script will generate MOF files in directory]
    Start-DscConfiguration -Path .\Windows_Server_2019_Firewall_Hardening  -Force -Verbose -Wait
#>

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
    Write-Host "You can now run your firewall hardening script." -ForegroundColor Green
}

# Configuration Definition
Configuration Windows_Server_2019_Firewall_Hardening {
    param (
        [string[]]$ComputerName = 'localhost'
    )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
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
Windows_Server_2019_Firewall_Hardening


# Check if MOF files were generated
$mofPath = "Windows_Server_2019_Firewall_Hardening\localhost.mof"
if (Test-Path $mofPath) {
    $mofFiles = Get-ChildItem -Path $mofPath -Filter "*.mof"
    if ($mofFiles.Count -gt 0) {
        Write-Host "MOF files successfully generated at: $mofPath" -ForegroundColor Green
        
        # ASK THE USER IF THEY WANT TO IMPLEMENT THE CONFIGURATION
        $implementConfig = Read-Host "Do you want to implement the firewall hardening configuration? (YES/NO)"
        
        # IF YES, EXECUTE THE START-DSCCONFIGURATION COMMAND
        if ($implementConfig -eq "YES") {
            Write-Host "Applying DSC configuration..." -ForegroundColor Yellow
            Start-DscConfiguration -Path .\Windows_Server_2019_Firewall_Hardening -Force -Verbose -Wait
            
            # Check configuration status
            $status = Get-DscConfigurationStatus
            if ($status.Status -eq "Success") {
                Write-Host "DSC Configuration applied successfully!" -ForegroundColor Green
            } else {
                Write-Host "DSC Configuration completed with status: $($status.Status)" -ForegroundColor Yellow
                Write-Host "Check the detailed logs for any issues." -ForegroundColor Yellow
            }
        } else {
            Write-Host "Configuration implementation skipped." -ForegroundColor Cyan
        }
    } else {
        Write-Host "No MOF files were generated. Check for errors in the configuration script." -ForegroundColor Red
    }
} else {
    Write-Host "MOF directory not found. The configuration may have failed to compile." -ForegroundColor Red
}