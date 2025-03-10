Function InstallHardeningKitty() {
    $Version = (((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).Name).SubString(2)
    $HardeningKittyLatestVersionDownloadLink = ((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).zipball_url
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $HardeningKittyLatestVersionDownloadLink -Out HardeningKitty$Version.zip
    Expand-Archive -Path ".\HardeningKitty$Version.zip" -Destination ".\HardeningKitty$Version" -Force
    $Folder = Get-ChildItem .\HardeningKitty$Version | Select-Object Name -ExpandProperty Name
    Move-Item ".\HardeningKitty$Version\$Folder\*" ".\HardeningKitty$Version\"
    Remove-Item ".\HardeningKitty$Version\$Folder\"
    New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
    Set-Location .\HardeningKitty$Version
    Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\HardeningKitty.psm1"
}
InstallHardeningKitty

# Create a custom Azure-friendly finding list for standalone (non-domain-joined) VMs
$originalList = "$listsPath\finding_list_msft_security_baseline_windows_server_2022_21h2_member_machine.csv"
$azureStandaloneList = "$listsPath\finding_list_msft_security_baseline_windows_server_2022_azure_standalone_.csv"

# Copy the original file
Copy-Item -Path $originalList -Destination $azureStandaloneList

# Read the CSV content
$content = Import-Csv -Path $azureStandaloneList

# Filter out settings that would break access to standalone VMs
$modifiedContent = $content | Where-Object {
    # Keep entries that don't match these problematic settings
    $_.ID -ne "2.2.22" -and  # "Deny log on through Remote Desktop Services"
    $_.ID -ne "2.2.7" -and   # "Deny log on through Remote Desktop Services"
    $_.ID -ne "1735" -and    # "Remote Desktop Session Host: Allow users to connect remotely by using Remote Desktop Services"
    $_.Name -ne "Deny log on through Remote Desktop Services" -and  # Exact match exclusion
    $_.Name -ne "Allow users to connect remotely by using Remote Desktop Services" -and  # Exact match exclusion
    $_.Name -notlike "*Deny*Remote*" -and
    $_.Name -notlike "*Deny log on through Remote Desktop*" -and  # Another pattern match
    $_.Name -notlike "*Allow users to connect remotely*" -and  # Pattern match for allow remote connections
    $_.Name -notlike "*Remote Desktop*deny*" -and
    $_.Name -notlike "*Remote Desktop*allow*" -and  # Pattern match for allow Remote Desktop
    $_.Name -notlike "*Remote Desktop*" -and  # ALL Remote Desktop settings to be safe
    $_.Registry -ne "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections" -and
    $_.RegistryItem -ne "fDenyTSConnections" -and  # Another way to catch the RDP denial setting
    $_.RegistryItem -ne "UserAuthentication" -and  # RDP authentication setting
    $_.Name -notlike "*local account*blank password*" -and
    $_.ID -ne "2.3.7.5" -and # Interactive logon: Smart card removal behavior
    $_.ID -notlike "2.3.1*" -and  # Account lockout policies (can lock you out if too aggressive)
    
    # Domain Controller related settings (won't work on standalone)
    $_.Name -notlike "*Domain Controller*" -and
    $_.Name -notlike "*Require Domain Controller authentication*" -and
    
    # Problematic authentication settings
    $_.ID -ne "10222" -and  # Network security: Minimum session security for NTLM SSP clients
    $_.ID -ne "10223" -and  # Network security: Minimum session security for NTLM SSP servers
    $_.Name -notlike "*NTLM*" -and  # Any NTLM restriction settings
    $_.RegistryItem -ne "NTLMMinClientSec" -and  # Another way to catch the NTLM session security
    $_.RegistryItem -ne "NTLMMinServerSec" -and  # Server-side NTLM security
    
    # Additional problematic settings
    $_.Name -notlike "*Smart card*" -and  # Smart card related settings
    $_.Name -notlike "*PKI*" -and  # Public Key Infrastructure settings
    $_.Name -notlike "*Kerberos*" -and  # Kerberos settings that might require domain
    $_.Name -notlike "*Secure Channel*" -and  # Secure channel data settings that require domain
    
    # User Rights Assignments that could affect RDP
    $_.Category -ne "User Rights Assignment" -and  # Exclude ALL user rights assignments to be safe
    $_.Name -notlike "*Allow log on through Remote Desktop*" -and
    $_.Name -notlike "*Deny log on through Remote Desktop*" -and
    $_.Name -notlike "*Allow log on*" -and
    $_.Name -notlike "*Deny log on*" -and
    
    # Terminal Services/RDP related registry settings
    $_.RegistryPath -notlike "*Terminal Services*" -and
    $_.RegistryPath -notlike "*TerminalServer*" -and
    
    # Network access policies
    $_.Name -notlike "*Network access*" -and
    $_.Name -notlike "*Network security*" -and
    
    # Remote connections
    $_.Name -notlike "*Allow users to connect remotely*" -and
    $_.Name -notlike "*Connect remotely*" -and  # Broader pattern for remote connection settings
    
    # Additional explicit user rights exclusions - make absolutely sure these are excluded
    $_.MethodArgument -ne "SeDenyRemoteInteractiveLogonRight" -and  # Exact match for denying remote logon
    $_.MethodArgument -notlike "*SeDenyRemoteInteractiveLogonRight*" -and  # Pattern match for denying remote logon
    $_.MethodArgument -notlike "*SeRemoteInteractiveLogonRight*" -and  # Right for allowing remote logon
    $_.MethodArgument -notlike "*SeInteractiveLogonRight*" -and  # Right for allowing interactive logon
    $_.MethodArgument -notlike "*SeDenyInteractiveLogonRight*" -and  # Right for denying interactive logon
    $_.RecommendedValue -notlike "*S-1-5-32-545*" -and  # This SID typically appears in Remote Desktop deny lists
    
    # Absolutely make sure NOTHING with SeDenyRemoteInteractiveLogonRight gets through
    ($_.RegistryPath -notlike "*SeDenyRemoteInteractiveLogonRight*" -and $_.RegistryItem -notlike "*SeDenyRemoteInteractiveLogonRight*")
}

# Export the modified list
$modifiedContent | Export-Csv -Path $azureStandaloneList -NoTypeInformation

# Run HardeningKitty with the filtered list
Invoke-HardeningKitty -Mode HailMary -SkipRestorePoint -FileFindingList $azureStandaloneList
