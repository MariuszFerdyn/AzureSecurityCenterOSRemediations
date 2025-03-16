# Windows Server 2022 Hardening Script for Azure Defender Recommendations
# Designed for non-domain joined servers
# Run as Administrator

<#
This script addresses the following security recommendations detected by Azure Defender's
"Vulnerabilities in security configuration on your Windows machines should be remediated (powered by Guest Configuration)"
that may not be covered by HardenKitty:

1. Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
2. Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
3. Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
4. Ensure 'Network security: Minimum session security for NTLM SSP based clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
5. Ensure 'Network security: Minimum session security for NTLM SSP based servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
6. Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'
7. System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies
8. Windows Firewall: Private: Allow unicast response
9. Windows Firewall: Public: Allow unicast response
10. Bypass traverse checking
11. Windows Firewall: Private: Allow unicast response (duplicate of #8)
12. Windows Firewall: Public: Allow unicast response (duplicate of #9)
13. Bypass traverse checking (duplicate of #10)
14. Increase a process working set
15. Caching of logon credentials must be limited
16. Users must be required to enter a password to access private keys stored on the computer
17. Accounts: Rename guest account
18. Account lockout policy

Note: "Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'"
is not implemented in this script but would be recommended as an additional hardening measure.
#>

# Function to log actions
function Write-Log {
    param (
        [string]$Message,
        [string]$Status = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Status] $Message"
    Add-Content -Path "$env:TEMP\WindowsHardening.log" -Value "[$timestamp] [$Status] $Message"
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "This script must be run as Administrator. Exiting." "ERROR"
    exit 1
}

Write-Log "Starting Windows Server 2022 Hardening Script..."

# Create a backup of the current security settings
$backupDate = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = "$env:USERPROFILE\Desktop\SecuritySettings_Backup_$backupDate.txt"
Write-Log "Creating backup of current security settings to $backupPath"
secedit /export /cfg $backupPath

try {
    # 1. Network access: Do not allow anonymous enumeration of SAM accounts and shares
    Write-Log "Setting 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled'"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord

    # 2. Network security: Allow Local System to use computer identity for NTLM
    Write-Log "Setting 'Network security: Allow Local System to use computer identity for NTLM' to 'Enabled'"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1 -Type DWord

    # 3. Network security: LAN Manager authentication level
    Write-Log "Setting 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM'"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord

    # 4. Network security: Minimum session security for NTLM SSP based clients
    Write-Log "Setting 'Network security: Minimum session security for NTLM SSP based clients' to 'Require NTLMv2 session security, Require 128-bit encryption'"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 0x20080000 -Type DWord

    # 5. Network security: Minimum session security for NTLM SSP based servers
    Write-Log "Setting 'Network security: Minimum session security for NTLM SSP based servers' to 'Require NTLMv2 session security, Require 128-bit encryption'"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 0x20080000 -Type DWord

    # 6. Windows Firewall: Private: Settings: Apply local connection security rules
    Write-Log "Setting 'Windows Firewall: Private: Settings: Apply local connection security rules' to 'Yes (default)'"
    # Using registry method as the parameter isn't directly accessible via Set-NetFirewallProfile
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "AllowLocalIPsecPolicyMerge" -Value 1 -Type DWord

    # 7. System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies
    Write-Log "Setting 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies'"
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "AuthenticodeEnabled" -Value 1 -Type DWord

    # 8 & 9, 11 & 12. Windows Firewall: Private/Public: Allow unicast response (appears twice in your list)
    Write-Log "Setting 'Windows Firewall: Private: Allow unicast response' to appropriate value"
    Set-NetFirewallProfile -Profile Private -AllowUnicastResponseToMulticast False
    
    Write-Log "Setting 'Windows Firewall: Public: Allow unicast response' to appropriate value"
    Set-NetFirewallProfile -Profile Public -AllowUnicastResponseToMulticast False

    # 10 & 13. Bypass traverse checking (appears twice in your list)
    Write-Log "Configuring 'Bypass traverse checking' privilege"
    try {
        # Creating a temporary security database
        $secDbPath = "$env:TEMP\secpol.sdb"
        $secpolPath = "$env:TEMP\secpol.cfg"
        
        # Export current security settings to work with
        secedit /export /cfg $secpolPath /quiet
        
        # Get the content of the file
        $secpolContent = Get-Content -Path $secpolPath -Raw
        
        # Update the SeChangeNotifyPrivilege setting (Bypass traverse checking)
        if ($secpolContent -match "\[Privilege Rights\]") {
            # If Privilege Rights section exists
            if ($secpolContent -match "SeChangeNotifyPrivilege\s*=.*") {
                # If the privilege already exists, replace it
                $secpolContent = $secpolContent -replace "SeChangeNotifyPrivilege\s*=.*", "SeChangeNotifyPrivilege = *S-1-5-32-544,*S-1-5-11,*S-1-5-19,*S-1-5-20"
            } else {
                # If the privilege doesn't exist, add it to the Privilege Rights section
                $secpolContent = $secpolContent -replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSeChangeNotifyPrivilege = *S-1-5-32-544,*S-1-5-11,*S-1-5-19,*S-1-5-20"
            }
        } else {
            # If Privilege Rights section doesn't exist, add it
            $secpolContent += "`r`n[Privilege Rights]`r`nSeChangeNotifyPrivilege = *S-1-5-32-544,*S-1-5-11,*S-1-5-19,*S-1-5-20"
        }
        
        # Write the updated content back to the file
        Set-Content -Path $secpolPath -Value $secpolContent
        
        # Import the updated security policy
        secedit /configure /db $secDbPath /cfg $secpolPath /areas USER_RIGHTS /quiet
        
        # Clean up temporary files
        Remove-Item -Path $secpolPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $secDbPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Error configuring 'Bypass traverse checking' privilege: $_" "ERROR"
    }

    # 14. Increase a process working set
    Write-Log "Configuring 'Increase a process working set' privilege"
    try {
        # Creating a temporary security database
        $secDbPath = "$env:TEMP\secpol2.sdb"
        $secpolPath = "$env:TEMP\secpol2.cfg"
        
        # Export current security settings to work with
        secedit /export /cfg $secpolPath /quiet
        
        # Get the content of the file
        $secpolContent = Get-Content -Path $secpolPath -Raw
        
        # Update the SeIncreaseWorkingSetPrivilege setting
        if ($secpolContent -match "\[Privilege Rights\]") {
            # If Privilege Rights section exists
            if ($secpolContent -match "SeIncreaseWorkingSetPrivilege\s*=.*") {
                # If the privilege already exists, replace it
                $secpolContent = $secpolContent -replace "SeIncreaseWorkingSetPrivilege\s*=.*", "SeIncreaseWorkingSetPrivilege = *S-1-5-32-544,*S-1-5-19"
            } else {
                # If the privilege doesn't exist, add it to the Privilege Rights section
                $secpolContent = $secpolContent -replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSeIncreaseWorkingSetPrivilege = *S-1-5-32-544,*S-1-5-19"
            }
        } else {
            # If Privilege Rights section doesn't exist, add it
            $secpolContent += "`r`n[Privilege Rights]`r`nSeIncreaseWorkingSetPrivilege = *S-1-5-32-544,*S-1-5-19"
        }
        
        # Write the updated content back to the file
        Set-Content -Path $secpolPath -Value $secpolContent
        
        # Import the updated security policy
        secedit /configure /db $secDbPath /cfg $secpolPath /areas USER_RIGHTS /quiet
        
        # Clean up temporary files
        Remove-Item -Path $secpolPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $secDbPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Error configuring 'Increase a process working set' privilege: $_" "ERROR"
    }
    Write-Log "Configuring 'Increase a process working set' privilege"
    try {
        # Creating a temporary security database
        $secDbPath = "$env:TEMP\secpol2.sdb"
        $secpolPath = "$env:TEMP\secpol2.cfg"
        
        # Export current security settings to work with
        secedit /export /cfg $secpolPath /quiet
        
        # Get the content of the file
        $secpolContent = Get-Content -Path $secpolPath -Raw
        
        # Update the SeIncreaseWorkingSetPrivilege setting
        if ($secpolContent -match "\[Privilege Rights\]") {
            # If Privilege Rights section exists
            if ($secpolContent -match "SeIncreaseWorkingSetPrivilege\s*=.*") {
                # If the privilege already exists, replace it
                $secpolContent = $secpolContent -replace "SeIncreaseWorkingSetPrivilege\s*=.*", "SeIncreaseWorkingSetPrivilege = *S-1-5-32-544,*S-1-5-19"
            } else {
                # If the privilege doesn't exist, add it to the Privilege Rights section
                $secpolContent = $secpolContent -replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSeIncreaseWorkingSetPrivilege = *S-1-5-32-544,*S-1-5-19"
            }
        } else {
            # If Privilege Rights section doesn't exist, add it
            $secpolContent += "`r`n[Privilege Rights]`r`nSeIncreaseWorkingSetPrivilege = *S-1-5-32-544,*S-1-5-19"
        }
        
        # Write the updated content back to the file
        Set-Content -Path $secpolPath -Value $secpolContent
        
        # Import the updated security policy
        secedit /configure /db $secDbPath /cfg $secpolPath /areas USER_RIGHTS /quiet
        
        # Clean up temporary files
        Remove-Item -Path $secpolPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $secDbPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Error configuring 'Increase a process working set' privilege: $_" "ERROR"
    }

    # 12. Caching of logon credentials must be limited
    Write-Log "Setting 'Caching of logon credentials must be limited'"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "4" -Type String

    # 13. Users must be required to enter a password to access private keys
    Write-Log "Setting 'Users must be required to enter a password to access private keys'"
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Name "ForceKeyProtection" -Value 2 -Type DWord

    # 14. Accounts: Rename guest account
    Write-Log "Renaming guest account"
    $newGuestName = "Visitor_" + (Get-Random -Minimum 10000 -Maximum 99999)
    Rename-LocalUser -Name "Guest" -NewName $newGuestName

    # 15. Account lockout policy
    Write-Log "Configuring account lockout policy"
    net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30

    # Save and apply security settings
    Write-Log "Saving and applying security settings"
    
    # Generate audit file to verify changes
    $auditPath = "$env:USERPROFILE\Desktop\SecuritySettings_Audit_$backupDate.txt"
    Write-Log "Creating audit of applied security settings to $auditPath"
    secedit /export /cfg $auditPath

    Write-Log "Windows Server 2022 Hardening Script completed successfully" "SUCCESS"
}
catch {
    Write-Log "An error occurred: $_" "ERROR"
    Write-Log "Script execution failed. Please check the log for details." "ERROR"
}
