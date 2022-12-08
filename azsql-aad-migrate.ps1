# https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?view=azuresql&tabs=azure-powershell


# this script is using SPN in TechPass to perform "Set admin" at Azure SQL server-level

try
{
    # mandatory env variables need to be set
    $techpass_SPNAppId = (Get-ChildItem env:azsqlaadm_SPNAppId).Value
    $techpass_techpass_tenant_id = (Get-ChildItem env:azsqlaadm_techpass_tenant_id).Value
    $techpass_spn_secret = (Get-ChildItem env:azsqlaadm_spn_secret).Value
    $techpass_sqladmin_username = (Get-ChildItem env:azsqlaadm_techpass_sqladmin_username).Value
    $techpass_sqladmin_objectid = (Get-ChildItem env:azsqlaadm_techpass_sqladmin_objectid).Value
    $sql_server_name = (Get-ChildItem env:azsqlaadm_sqlserver_name).Value
    $sql_server_resourcegroup = (Get-ChildItem env:azsqlaadm_rg).Value
}
catch
{
    Error "Something threw an exception"
  
}

$tenantId = $techpass_techpass_tenant_id
$secPassword = ConvertTo-SecureString -AsPlainText -Force -String $techpass_spn_secret
$azcredSPN = New-Object System.Management.Automation.PSCredential $techpass_SPNAppId, $secPassword

# login to Azure techpass tenant
Info "authenticating to AAD"
Connect-AzAccount -ServicePrincipal -Credential $azcredSPN -Tenant $tenantId
Info "authenticated to AAD"

Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $sql_server_resourcegroup `
-ServerName $sql_server_name `
-ObjectId $techpass_sqladmin_objectid `
-DisplayName $techpass_sqladmin_username


# migrate for server-level logins


# migrate for db users




Function Info($msg) {
    Write-Host $msg -fore green
}
Function Error($msg) {
    Write-Host $msg -fore red
}