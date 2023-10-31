# This process will create a Policy Initiative with all the policies that do not need to provide any parameters. Microsoft cloud security benchmark covers only about 235 policies, in that way deploys almost 400 compliance policies.

## Log in to Azure and select subscription

```
Connect-AzAccount -UseDeviceAuthentication -Tenant "TenantId"
Set-AzContext -Subscription "SubscriptionID"
```

## List all build-in policies
```
Get-AzPolicyDefinition -Builtin
```
## Save the policiy to the file
```
Get-AzPolicyDefinition -Builtin|Select ResourceName|Out-File policies.txt
```

## Create temporary resource group, that will be used for assigning the policy to test if it can be done without any parameters.
```
New-AzResourceGroup -Name "mariusz-test-policy-01" -Location "West Europe"
```

## Execute script to test if it can be done without any parameters.

```
# Import-Module Az.Resources

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

foreach( $policy in $listPolicy)
{

    $definition = Get-AzPolicyDefinition -Name $policy

    # remove [] from name (like [Preview] - these characters are not accepted in the name
    $newName = $definition.Properties.DisplayName.Replace("[", "").Replace("]","")

    if($newName.Length -gt 63)
    {
        $newName = $newName.SubString(0,63)
    }

    New-AzPolicyAssignment -Scope $resourceGroup.ResourceId -PolicyDefinition $definition -Name $newName 

    if( -not $? )
    {
        $msg = $Error[0].Exception.Message

        # Remove special char of new line in error
        $msg = $msg.Replace("`n",", ").Replace("`r",", ")

        Add-Content "log.txt"  $policy": "$msg
        
    }
    else {
        Add-Content "log.txt" $policy": OK"
    }
}
```
