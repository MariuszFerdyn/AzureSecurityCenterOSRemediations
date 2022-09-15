#Connect-AzAccount
#Activate PIM
$SubscriptionID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$TenantID= "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$RG="Group01"

Select-AzSubscription -SubscriptionId $SubscriptionID -Tenant $TenantID

$vms = get-azvm -ResourceGroupName $RG

foreach ($vm in $vms) {
    # Check if the resource is a regular virtual machine or Azure Arc connected
    if (($vm.Id -split '\/')[-3] -match "Microsoft.Compute") {
        $vmName = ($vm.Id -split '\/')[-1]
        Write-Host "Working on $vmName" -ForegroundColor Green
        $vmStatus = Invoke-AzRestMethod -Path ('{0}/instanceView?api-version=2020-06-01' -f $vm.Id) -Method GET |
        Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty Statuses
        if ($vmStatus.displayStatus -match 'VM running') {
            $res = Invoke-AzRestMethod -Path ('{0}/providers/Microsoft.Security/serverVulnerabilityAssessments/default?api-Version=2015-06-01-preview' -f $vm.Id) -Method PUT
            if ($res.StatusCode -notmatch '200|202') {
                Write-Host ($res.Content | ConvertFrom-Json).Error.message -ForegroundColor Red
            }
        }
        else {
            Write-Host "$vmName is currently stopped. Skipping this one" -ForegroundColor Yellow
        }
    }
    else {
        $vmName = ($vm.Id -split '\/')[-1]
        Write-Host "Working on $vmName" -ForegroundColor Green
        $vmStatus = Invoke-AzRestMethod -Path ('{0}?api-version=2019-12-12' -f $vm.Id) -Method GET |
        Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty properties
        if ($vmStatus.status -match 'Connected') {
            $res = Invoke-AzRestMethod -Path ('{0}/providers/Microsoft.Security/serverVulnerabilityAssessments/default?api-Version=2015-06-01-preview' -f $vm.Id) -Method PUT
            if ($res.StatusCode -notmatch '200|202') {
                Write-Host ($res.Content | ConvertFrom-Json).Error.message -ForegroundColor Red
            }
        }
        else {
            Write-Host "$vmName is currently stopped. Skipping this one" -ForegroundColor Yellow
        }
    } 
}

