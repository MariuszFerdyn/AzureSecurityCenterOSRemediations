# This process will create a Policy Initiative with all the policies that do not need to provide any parameters. Microsoft cloud security benchmark covers only about 235 policies, in that way deploys almost 400 compliance policies.

## Log in to Azure and select subscription

```
Connect-AzAccount -UseDeviceAuthentication -Tenant "TenantId"
Set-AzContext -Subscription "SubscriptionID"
```

## Install ResourceGraph Module (need admin rights)
```
Install-Module Az.ResourceGraph
```
## List all build-in policies
```
Get-AzPolicyDefinition -Builtin
```
## List all build-in policies (make sure the directory where you executed script are empty - no policies.txt)
```
 Get-AzPolicyDefinition -Builtin|Select PolicyDefinitionId|Out-File policies.txt
```

### ** Not in use *** Save the policiy to the file, make sure the directory where you executed script are empty (no policies.txt). In this query we filter only build-in policies with AuditIfNotExists efect.
```
Import-Module Az.ResourceGraph
$query = @"
policyresources 
| where type == 'microsoft.authorization/policydefinitions' 
| where properties.policyType == 'BuiltIn'
| extend policyDefinitionId = tolower(tostring(id)), policyDefinitionDisplayName = properties.displayName, policyDefinitionEffect = properties.policyRule.then.effect, policyDefinitionEffectDefaultValue = properties.parameters.effect.defaultValue
| where policyDefinitionEffect == 'AuditIfNotExists' or policyDefinitionEffectDefaultValue == 'AuditIfNotExists'
| project split(policyDefinitionId,"/")[4]
"@
$policies = Search-AzGraph -Query $query -UseTenantScope -First 1000

$fileName="policies.txt"
$policies|Out-File $fileName -Append
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

## Execute script to test if policy can be assigned without any parameters with effect auditIfNotExists. The problems will go to the log.txt and policies without problem will go to policies-AuditIfNotExists-ok.txt (check if you do not have the files in current directory before execution).

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
Set-Content "log.txt" "Report of assignment of policies"

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

        Add-Content "log.txt"  $policy": "$msg
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


## Execute script to test if policy can be assigned without any parameters with effect Audit. The problems will go to the log.txt and policies without problem will go to policies-Audit-ok.txt (check if you do not have the files in current directory before execution).

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
Set-Content "log.txt" "Report of assignment of policies"

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

        Add-Content "log.txt"  $policy": "$msg
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


## Create a json with initative.
```
$1st='$policyDefinitions = @"['
$2nd='{"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/'
$3rd='","parameters": {"effect": {"value": "AuditIfNotExists"}}},},'
$listPolicy = Get-Content -Path ".\policies-ok.txt"
Set-Content 'initiative.json' $1st
foreach( $policy in $listPolicy)
{
$pol=$2nd
$pol=$pol+$policy
$pol=$pol+$policy+$3rd
Add-Content 'initiative.json' $pol
}
```
