# Policy Initiative Creation Script

This script creates a Policy Initiative (`policy.json`) containing all Azure built-in policies that do not require parameters.  
While the Microsoft Cloud Security Benchmark covers approximately 235 policies, this script enables deployment of over 950 Azure built-in compliance policies for broader coverage.

## Output Files

The script generates the following files:

- `policies-AuditIfNotExists-ok.txt` – Contains all policies that do not require parameters, along with detailed explanations.  
- `log-auditIfNotExists.txt` – Contains policies that require parameters and those with a default action of *Deny* that can optionally be deployed as *Audit*.  
- `initiative.json` – A JSON file that can be used directly to deploy the initiative.

## Manual Deployment (Without Running the Script)

You can deploy the initiative manually if you prefer not to run the script.

1. Download the `initiative.json` file.  
2. Execute the following command in PowerShell:
   ```
   New-AzPolicySetDefinition -Name 'TotalSecurity' -PolicyDefinition initiative.json
   ```
3. Assign the initiative to the desired scope.

## The script
```
#Connect-AzAccount -Tenant xxx
#Set-AzContext -Subscription xxx
Get-AzPolicyDefinition -Builtin|Select Name|Out-File policies.txt
(Get-Content policies.txt | Select-Object -Skip 3) | Set-Content policies.txt
(Get-Content policies.txt).Replace('/providers/Microsoft.Authorization/policyDefinitions/', '') | Set-Content policies.txt
New-AzResourceGroup -Name "mariusz-test-policy-01" -Location "West Europe" -Force
Import-Module Az.Resources
# Remove annoying prompts
$ErrorActionPreference = "SilentlyContinue"
# Name of Resource Group 
$resourceGroupName="mariusz-test-policy-01"
# Get file with policies
# policy per line
$listPolicy = Get-Content -Path ".\policies.txt"
$resourceGroup = Get-AzResourceGroup -Name $resourceGroupName
Remove-AzPolicyAssignment -Name "TestAssigment" -Scope $resourceGroup.ResourceId
# Create file with logs
Set-Content "log-auditIfNotExists.txt" "Report of assignment of policies"
$okCount = 0
$problemsCount = 0
$okRaport = "policies-AuditIfNotExists-ok.txt"
foreach( $policy in $listPolicy)
{
    $definition = Get-AzPolicyDefinition -Name $policy
    ###Test###
    #$definition = Get-AzPolicyDefinition -Name "b0eb591a-5e70-4534-a8bf-04b9c489584a"   #With Parameters
    #$definition = Get-AzPolicyDefinition -Name "7aa1c9d5-3d7e-4579-8117-d85e99211757"   #DefaultDeny
    #$definition = Get-AzPolicyDefinition -Name "426c172c-9914-10d1-25dd-669641fc1af4"   #Manual
    #$definition = Get-AzPolicyDefinition -Name "1c988dd6-ade4-430f-a608-2a3e5b0a6d38"   #AudifIfNotExist
    #$definition = Get-AzPolicyDefinition -Name "2a1a9cdf-e04d-429a-8416-3bfb72a1b26f"   #Audit
    #$definition = Get-AzPolicyDefinition -Name "0015ea4d-51ff-4ce3-8d8c-f3f8f0179a56"   #Without Parameters
    #$definition = Get-AzPolicyDefinition -Name "0015ea4d-51ff-4ce3-8d8c-f3f8f0179a56"   #Empty
    ##########
    $displayName = $definition.DisplayName
    $newName = $displayName.Replace("[", "").Replace("]","")
    if($newName.Length -gt 63)
    {
        $newName = $newName.SubString(0,63)
    }
    Remove-AzPolicyAssignment -Name "TestAssigment" -Scope $resourceGroup.ResourceId
    New-AzPolicyAssignment -Scope $resourceGroup.ResourceId -PolicyDefinition $definition -Name "TestAssigment"
    
    # Test if the policy assignment was actually created
    $assignmentCheck = Get-AzPolicyAssignment -Name "TestAssigment" -Scope $resourceGroup.ResourceId
    
    if($assignmentCheck)
    {
        $def = Get-AzPolicyDefinition -BackwardCompatible -Id $assignmentCheck.PolicyDefinitionId
        $defaction=$def.Properties.Parameters.effect.defaultValue
        # If $defaction is empty, get the effect from policyRule
        if([string]::IsNullOrEmpty($defaction))
        {
            $defaction = $def.policyRule.then.effect
        }
        # Check if the effect is Audit or AuditIfNotExists
        if($defaction -eq "Audit" -or $defaction -eq "AuditIfNotExists")
        {
            # Assignment was created successfully with correct effect
            $okMessage = $policy + "," + $newName
            Add-Content $okRaport $okMessage
            Write-Host "OK: $okMessage" -ForegroundColor Green
            $okCount++
        }
        else
        {
            # Assignment created but effect is not Audit or AuditIfNotExists
            $logMessage = $policy + "," + $newName + "," + $defaction
            Add-Content "log-auditIfNotExists.txt" $logMessage
            Write-Host "Warning (Wrong Effect): $logMessage" -ForegroundColor Yellow
            $problemsCount++
        }
        
        Remove-AzPolicyAssignment -Name "TestAssigment" -Scope $resourceGroup.ResourceId
    }
    else
    {
        # Assignment was not created
        $logMessage = $policy + "," + $newName + ",Assigment Not Created - propably parameters needed"
        Add-Content "log-auditIfNotExists.txt" $logMessage
        Write-Host "PROBLEM (Not Created): $logMessage" -ForegroundColor Red
        $problemsCount++
        Remove-AzPolicyAssignment -Name "TestAssigment" -Scope $resourceGroup.ResourceId
    }
}
Write-Host("Raport of assigments, ok: " + $okCount + ", problems: " + $problemsCount)
# Build initiative.json properly
$listPolicy = Get-Content -Path ".\policies-AuditIfNotExists-ok.txt"
$jsonArray = @()
foreach( $policy in $listPolicy)
{
    # Skip policies containing "Deprecated" or "Preview"
    if($policy -match "Deprecated|Preview")
    {
        continue
    }
    
    # Extract only the policy ID (part before the comma)
    $policyId = $policy.Split(',')[0]
    $jsonArray += '{"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/' + $policyId + '"}'
}
# Join with commas and wrap in brackets
$jsonContent = '[' + "`r`n" + ($jsonArray -join ",`r`n") + "`r`n" + ']'
Set-Content 'initiative.json' $jsonContent
New-AzPolicySetDefinition -Name 'TotalSecurity' -PolicyDefinition initiative.json
```
