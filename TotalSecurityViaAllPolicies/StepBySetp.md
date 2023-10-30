# This process will create a Policy Initiative with all the policies that do not need to provide any parameters. Microsoft cloud security benchmark covers only about 235 policies, in that way deploys almost 400 compliance policies.

## Log in to Azure and select subscription

```
Connect-AzAccount -UseDeviceAuthentication -Tenant "TenantId"
Set-AzContext -Subscription "SubscriptionID"
```

## List all 
