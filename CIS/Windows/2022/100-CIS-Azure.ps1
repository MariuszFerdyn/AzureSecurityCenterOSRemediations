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




# If HardeningKitty is installed as a module
$modulePath = (Get-Module -ListAvailable -Name HardeningKitty | Select-Object -ExpandProperty Path)
$listsPath = Join-Path -Path (Split-Path -Parent $modulePath) -ChildPath "lists"

# Or manually navigate to the lists folder if you know where it is
# $listsPath = "C:\path\to\HardeningKitty\lists"

# List all finding lists
Get-ChildItem -Path $listsPath -Filter "finding_list*.csv"


Invoke-HardeningKitty -Mode Config -Report -ReportFile report1.csv



# Create a custom Azure-friendly finding list for standalone (non-domain-joined) VMs
$originalList = "$listsPath\finding_list_cis_microsoft_windows_server_2022_22h2_3.0.0_machine.csv"
$azureStandaloneList = "$listsPath\finding_list_cis_azure_standalone_vm_2022.csv"

# Copy the original file
Copy-Item -Path $originalList -Destination $azureStandaloneList

# Read the CSV content
$content = Import-Csv -Path $azureStandaloneList

# Filter out settings that would break RDP access
$modifiedContent = $content | Where-Object {
    # Keep entries that don't match these problematic settings
    $_.ID -ne "2.2.22" -and  # "Deny log on through Remote Desktop Services"
    $_.ID -ne "2.2.7" -and   # "Deny log on through Remote Desktop Services"
    $_.Name -notlike "*Deny*Remote*" -and
    $_.Name -notlike "*Remote Desktop*deny*" -and
    $_.Registry -ne "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDenyTSConnections" -and
    $_.Name -notlike "*local account*blank password*" -and
    $_.ID -ne "2.3.7.5" -and # Interactive logon: Smart card removal behavior
    $_.ID -notlike "2.3.1*"  # Account lockout policies (can lock you out if too aggressive)
}

# Export the modified list
$modifiedContent | Export-Csv -Path $azureStandaloneList -NoTypeInformation

# Run HardeningKitty with the filtered list
Invoke-HardeningKitty -Mode HailMary -SkipRestorePoint -FileFindingList $azureStandaloneList


Invoke-HardeningKitty -Mode HailMary -SkipRestorePoint -FileFindingList $listsPath\finding_list_cis_microsoft_windows_server_2022_22h2_3.0.0_user.csv 
