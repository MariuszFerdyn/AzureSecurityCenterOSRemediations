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
## Save the policiy to the file, make sure the directory where you executed script are empty (no policies.txt). In this query we filter only build-in policies with AuditIfNotExists efect.
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

$number=0
foreach ($policy in $policies){
    if($number -lt 1){
        Out-File $fileName
    }

    $policy.policyDefinitionId_4 | Out-File $fileName -Append
}
```

## Remove first 3 lines with headers
```
(Get-Content policies.txt | Select-Object -Skip 3) | Set-Content policies.txt
```

## Create temporary resource group, that will be used for assigning the policy to test if it can be done without any parameters. Make sure it is not exist before.
```
New-AzResourceGroup -Name "mariusz-test-policy-01" -Location "West Europe"
```

## Execute script to test if policy can be assigned without any parameters with effect auditIfNotExists. The results will go to the log.txt

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

$okRaport = "policies-ok.txt"

foreach( $policy in $listPolicy)
{

    $definition = Get-AzPolicyDefinition -Name $policy

    # remove [] from name (like [Preview] - these characters are not accepted in the name
    $newName = $definition.Properties.DisplayName.Replace("[", "").Replace("]","")

    if($newName.Length -gt 63)
    {
        $newName = $newName.SubString(0,63)
    }

    New-AzPolicyAssignment -Scope $resourceGroup.ResourceId -PolicyDefinition $definition -Name $newName -PolicyParameterObject @{"effect"="AuditIfNotExists"}

    if( -not $? )
    {
        $msg = $Error[0].Exception.Message

        # Remove special char of new line in error
        $msg = $msg.Replace("`n",", ").Replace("`r",", ")

        Add-Content "log.txt"  $policy": "$msg
        $problemsCount++
        
    }
    else {
        Add-Content $okRaport $policy
        $okCount++
    }
}

Write-Host("Raport of assigments, ok: " + $okCount + ", problems: " + $problemsCount)

if ($okCount -gt 0){
    $listPolicy = Get-Content -Path $okRaport

    foreach( $policy in $listPolicy) {
        $definition = Get-AzPolicyDefinition -Name $policy

        # remove [] from name (like [Preview] - these characters are not accepted in the name
        $newName = $definition.Properties.DisplayName.Replace("[", "").Replace("]","")
    
        if($newName.Length -gt 63)
        {
            $newName = $newName.SubString(0,63)
        }
        Remove-AzPolicyAssignment -Name $newName -Scope $resourceGroup.ResourceId
    }


}
```
