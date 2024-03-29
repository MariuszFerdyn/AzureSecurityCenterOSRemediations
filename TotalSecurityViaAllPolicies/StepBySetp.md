# This process will create a Policy Initiative with all the policies that do not need to provide any parameters. Microsoft cloud security benchmark covers only about 235 policies, in that way deploys almost 480+ Azure build-in compliance policies.

## Log in to Azure and select subscription

```
Connect-AzAccount -UseDeviceAuthentication -Tenant "TenantId"
Set-AzContext -Subscription "SubscriptionID"
```

## Install ResourceGraph Module (need admin rights). If you do not want generate policies to implement yourself you can use predefinied from this repository, so you can skip to penultimate point in this manual.
```
Install-Module Az.ResourceGraph
```
## List all build-in policies
```
Get-AzPolicyDefinition -Builtin|ConvertTo-Json
```
## List all build-in policies and write it to file. (make sure the directory where you executed script are empty - no policies.txt)
```
 Get-AzPolicyDefinition -Builtin|Select PolicyDefinitionId|Out-File policies.txt
```

## Remove first 3 lines with headers
```
(Get-Content policies.txt | Select-Object -Skip 3) | Set-Content policies.txt
```
## Left only policy id in file
```
(Get-Content policies.txt).Replace('/providers/Microsoft.Authorization/policyDefinitions/', '') | Set-Content policies.txt
```

## Create temporary resource group, that will be used for assigning the policy to test if it can be done without any parameters. Make sure it is not exist before.
```
New-AzResourceGroup -Name "mariusz-test-policy-01" -Location "West Europe"
```

## Execute script to test if policy can be assigned without any parameters with effect auditIfNotExists. The problems will go to the log-auditIfNotExists.txt and policies without problem will go to policies-AuditIfNotExists-ok.txt (check if you do not have the files in current directory before execution).

```
Import-Module Az.Resources

# Remove annoying prompts
$ErrorActionPreference = "SilentlyContinue"

# Name of Resource Group 
$resourceGroupName="mariusz-test-policy-01"

# Get file with policies
# policy per line
$listPolicy = Get-Content -Path ".\policies.txt"

$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName

# Create file with logs
Set-Content "log-auditIfNotExists.txt" "Report of assignment of policies"

$okCount = 0
$problemsCount = 0

$okRaport = "policies-AuditIfNotExists-ok.txt"

foreach( $policy in $listPolicy)
{

    $definition = Get-AzPolicyDefinition -Name $policy

    $newName = $definition.Properties.DisplayName.Replace("[", "").Replace("]","")

    if($newName.Length -gt 63)
    {
        $newName = $newName.SubString(0,63)
    }

    New-AzPolicyAssignment -Scope $resourceGroup.ResourceId -PolicyDefinition $definition -Name "TestAssigment" -PolicyParameterObject @{"effect"="AuditIfNotExists"}

    if( -not $? )
    {
        $msg = $Error[0].Exception.Message

        # Remove special char of new line in error
        $msg = $msg.Replace("`n",", ").Replace("`r",", ")
        $msg = $newName + " " + $msg

        Add-Content "log-auditIfNotExists.txt"  $policy": "$msg
        $problemsCount++
        
    }
    else {
        Add-Content $okRaport $policy
        $okCount++
        Remove-AzPolicyAssignment -Name "TestAssigment" -Scope $resourceGroup.ResourceId
    }
}

Write-Host("Raport of assigments, ok: " + $okCount + ", problems: " + $problemsCount)
```


## Execute script to test if policy can be assigned without any parameters with effect Audit. The problems will go to the log-Audit.txt and policies without problem will go to policies-Audit-ok.txt (check if you do not have the files in current directory before execution).

```
Import-Module Az.Resources

# Remove annoying prompts
$ErrorActionPreference = "SilentlyContinue"

# Name of Resource Group 
$resourceGroupName="mariusz-test-policy-01"

# Get file with policies
# policy per line
$listPolicy = Get-Content -Path ".\policies.txt"

$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName

# Create file with logs
Set-Content "log-Audit.txt" "Report of assignment of policies"

$okCount = 0
$problemsCount = 0

$okRaport = "policies-Audit-ok.txt"

foreach( $policy in $listPolicy)
{

    $definition = Get-AzPolicyDefinition -Name $policy

    $newName = $definition.Properties.DisplayName.Replace("[", "").Replace("]","")

    if($newName.Length -gt 63)
    {
        $newName = $newName.SubString(0,63)
    }

    New-AzPolicyAssignment -Scope $resourceGroup.ResourceId -PolicyDefinition $definition -Name "TestAssigment" -PolicyParameterObject @{"effect"="Audit"}

    if( -not $? )
    {
        $msg = $Error[0].Exception.Message

        # Remove special char of new line in error
        $msg = $msg.Replace("`n",", ").Replace("`r",", ")
        $msg = $newName + " " + $msg

        Add-Content "log-Audit.txt"  $policy": "$msg
        $problemsCount++
        
    }
    else {
        Add-Content $okRaport $policy
        $okCount++
        Remove-AzPolicyAssignment -Name "TestAssigment" -Scope $resourceGroup.ResourceId
    }
}

Write-Host("Raport of assigments, ok: " + $okCount + ", problems: " + $problemsCount)
```


## Create a json with initative. Check if initiative.json doesn't exist in current directory.
```
$1st='['
$2nd='{"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/'
$3rd='","parameters": {"effect": {"value": "AuditIfNotExists"}}},'
$listPolicy = Get-Content -Path ".\policies-AuditIfNotExists-ok.txt"
Set-Content 'initiative.json' $1st
foreach( $policy in $listPolicy)
{
$pol=$2nd
$pol=$pol+$policy
$pol=$pol+$3rd
Add-Content 'initiative.json' $pol
}
$3rd='","parameters": {"effect": {"value": "Audit"}}},'
$listPolicy = Get-Content -Path ".\policies-Audit-ok.txt"
foreach( $policy in $listPolicy)
{
$pol=$2nd
$pol=$pol+$policy
$pol=$pol+$3rd
Add-Content 'initiative.json' $pol
}
$stream = [IO.File]::OpenWrite('initiative.json')
$stream.SetLength($stream.Length - 2)
$stream.Close()
$stream.Dispose()
$4rd=']'
Add-Content 'initiative.json' $4rd
```
## Create initiative with Name TotalSecurity - To be honest you can skip all the above steps and download the initiative.json from this repo and just execute this command.
```
New-AzPolicySetDefinition -Name 'TotalSecurity' -PolicyDefinition initiative.json
```
## Now you can assign the initiative to suscription or managed group
