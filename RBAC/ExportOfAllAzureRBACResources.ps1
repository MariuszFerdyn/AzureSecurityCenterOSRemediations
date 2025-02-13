# Connect to both Azure and Azure AD
#Connect-AzAccount
#Connect-AzureAD
$SubscriptionId="bbeef65c-98b2-4151-be75-52efe1c835a5"

# Function to get all group members including nested groups
function Get-AllGroupMembers {
    param (
        [string]$GroupID
    )
    $Members = @()
    # Get direct members of the group
    $DirectMembers = Get-AzureADGroupMember -ObjectId $GroupID -All $true
    $GroupName = (Get-AzureADGroup -ObjectId $GroupID).DisplayName
    
    foreach ($Member in $DirectMembers) {
        if ($Member.ObjectType -eq "User") {
            # Create custom object with user and source group info
            $MemberInfo = [PSCustomObject]@{
                DisplayName = $Member.DisplayName
                UserPrincipalName = $Member.UserPrincipalName
                SourceGroup = $GroupName
            }
            $Members += $MemberInfo
        } elseif ($Member.ObjectType -eq "Group") {
            # Recursively get members of nested groups
            $Members += Get-AllGroupMembers -GroupID $Member.ObjectId
        }
    }
    return $Members | Sort-Object -Property UserPrincipalName -Unique
}


# Create array to store results
$results = @()

# Determine which subscriptions to process
if ($SubscriptionId) {
    # Get specific subscription
    $subscriptions = Get-AzSubscription -SubscriptionId $SubscriptionId
    if (-not $subscriptions) {
        Write-Error "Subscription with ID '$SubscriptionId' not found."
        exit
    }
} else {
    # Get all subscriptions
    $subscriptions = Get-AzSubscription
}

foreach ($subscription in $subscriptions) {
    # Set context to current subscription
    Set-AzContext -Subscription $subscription.Id | Out-Null
    Write-Host "Processing subscription: $($subscription.Name)"
    
    # Get all resources in the subscription
    $resources = Get-AzResource
    
    foreach ($resource in $resources) {
        Write-Host "Processing resource: $($resource.Name)"
        
        # Get role assignments for the resource
        $roleAssignments = Get-AzRoleAssignment -Scope $resource.ResourceId
        
        foreach ($roleAssignment in $roleAssignments) {
            if ($roleAssignment.ObjectType -eq 'Group') {
                # Get all users from the group using the new function
                $groupUsers = Get-AllGroupMembers -GroupID $roleAssignment.ObjectId
                
                # Add each user from the group to results
                foreach ($user in $groupUsers) {
                    $results += [PSCustomObject]@{
                        SubscriptionName = $subscription.Name
                        SubscriptionId = $subscription.Id
                        ResourceGroup = $resource.ResourceGroupName
                        ResourceName = $resource.Name
                        ResourceType = $resource.ResourceType
                        RoleDefinitionName = $roleAssignment.RoleDefinitionName
                        PrincipalType = 'User'
                        PrincipalName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        GroupPath = $user.SourceGroup
                    }
                }
            }
            else {
                # Add direct assignment
                $results += [PSCustomObject]@{
                    SubscriptionName = $subscription.Name
                    SubscriptionId = $subscription.Id
                    ResourceGroup = $resource.ResourceGroupName
                    ResourceName = $resource.Name
                    ResourceType = $resource.ResourceType
                    RoleDefinitionName = $roleAssignment.RoleDefinitionName
                    PrincipalType = $roleAssignment.ObjectType
                    PrincipalName = $roleAssignment.DisplayName
                    UserPrincipalName = $roleAssignment.SignInName
                    GroupPath = 'Direct Assignment'
                }
            }
        }
    }
}

# Export results to CSV
$outputPath = ".\RBACPermissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $outputPath -NoTypeInformation

Write-Host "Export completed. File saved to: $outputPath"
