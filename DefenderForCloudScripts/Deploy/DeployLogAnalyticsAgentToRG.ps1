$ErrorActionPreference = 'Stop'
#Connect-AzAccount
#Activate PIM
$SubscriptionID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$TenantID= "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$RG="Group01"
$workspaceId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$workspaceKey = "xxx"

$PublicSettings = @{"workspaceId" = $workspaceId;"stopOnMultipleConnections" = $false}
$ProtectedSettings = @{"workspaceKey" = $workspaceKey}

Select-AzSubscription -SubscriptionId $SubscriptionID -Tenant $TenantID

$targetVMs = get-azvm -ResourceGroupName $RG
foreach($VM in $targetVMs)
{
    Write-Output "`r`n"
    Write-Host "*** Trying to install the MMA VM extension on" $VM.Name -ForegroundColor Green
    if ($VM.StorageProfile.OsDisk.OsType -eq "Windows") {
        try
        {
            Write-Host "Installing VM Extension of type Windows....please wait..." -ForeGroundColor Green
            try
            {
                # check if the VM extension has already been installed
                Get-AzVMExtension -VMName $VM.Name -ResourceGroupName $VM.ResourceGroupName -Name "MicrosoftMonitoringAgent" | Select-Object VMName, ProvisioningState, ResourceGroupName
                Write-Host "Extension has already been installed, so skipping...." -ForegroundColor Red

            }
            catch
            {
                Set-AzVMExtension -VMName $VM.Name -ResourceGroupName $VM.ResourceGroupName `
                -Name MicrosoftMonitoringAgent `
                -TypeHandlerVersion 1.0 `
                -Publisher Microsoft.EnterpriseCloud.Monitoring  `
                -ExtensionType MicrosoftMonitoringAgent `
                -Settings $publicSettings `
                -ProtectedSettings $protectedSettings `
                -Location $VM.Location
                Write-Host "Done!" -ForeGroundColor Green
            }

        
        }
        catch {Write-Host "Could not set subscription or could not install the VM extension" -ForegroundColor Red}
        
    }
    #VM is of type Linux
    elseif ($VM.StorageProfile.OsDisk.OsType -eq "Linux") {
        Write-Host "Installing VM Extension of type Linux....please wait..." -ForeGroundColor Green
        try
        {
            # check if the VM extension has already been installed
            Get-AzVMExtension -VMName $VM.Name -ResourceGroupName $VM.ResourceGroupName -Name "MicrosoftMonitoringAgent" | Select-Object VMName, ProvisioningState, ResourceGroupName
            Write-Host "Extension has already been installed, so skipping...." -ForegroundColor Red

        }
        catch
        {
            Set-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -ExtensionName OmsAgentForLinux -ExtensionType OmsAgentForLinux -Publisher Microsoft.EnterpriseCloud.Monitoring -TypeHandlerVersion 1.7 -ProtectedSettings $protectedSettings -Settings $publicSettings -Location $VM.Location
            Write-Host "Done!" -ForeGroundColor Green
        }
    }
    else {
        Write-Host "No valid OS type found!" -ForegroundColor Red
    }
}
