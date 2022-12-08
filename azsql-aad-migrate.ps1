# https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?view=azuresql&tabs=azure-powershell


# this script is using SPN in TechPass to perform "Set admin" at Azure SQL server-level

# try
# {
#     # mandatory env variables need to be set
#     #$techpass_SPNAppId = (Get-ChildItem env:azsqlaadm_SPNAppId).Value
    
#     #$techpass_spn_secret = (Get-ChildItem env:azsqlaadm_spn_secret).Value
    
#     #$techpass_sqladmin_objectid = (Get-ChildItem env:azsqlaadm_techpass_sqladmin_objectid).Value
    
# }
# catch
# {
#     Error("Something threw an exception")
  
# }


Function SetupPrequisites() {

    try {
        $global:techpass_techpass_tenant_id = (Get-ChildItem env:azsqlaadm_techpass_tenant_id).Value
        $global:aad_sqladmin_username = (Get-ChildItem env:azsqlaadm_aad_sqladmin_username).Value
        $global:aad_sqladmin_password = (Get-ChildItem env:azsqlaadm_aad_sqladmin_password).Value
        $global:sql_server_name = (Get-ChildItem env:azsqlaadm_sqlserver_name).Value
        #$global:sql_server_resourcegroup = (Get-ChildItem env:azsqlaadm_rg).Value

        $aadADminPassword = ConvertTo-SecureString -AsPlainText -Force -String $aad_sqladmin_password 
        $azcred = New-Object System.Management.Automation.PSCredential $aad_sqladmin_username, $aadADminPassword

        # login to Azure techpass tenant
        # Info "authenticating to AAD"
        # Connect-AzAccount -Credential $azcred -Tenant $techpass_techpass_tenant_id
        # $global:accesstoken = Get-AzAccessToken

        $global:sqlConn = new-object System.Data.SqlClient.SqlConnection("Data Source=$sql_server_name; Authentication=Active Directory Password; Initial Catalog=master;  UID=$aad_sqladmin_username; PWD=$aad_sqladmin_password")
        #$global:sqlConn.AccessToken = $accesstoken.Token
    
    }
    catch {
        $errMsg = $Error[0]
        Error "error at setting up prerequisites, $errMsg" "SetupPrequisites"
     }
}

Function Info($msg) {
    Write-Host $msg -fore green
}
Function Error($msg, $source) {
    Write-Host "($source): $msg" -fore red
}

Function IsNullOrEmptyStr($str) {
    if ( $null -eq $str -Or [string]::IsNullOrEmpty($str)) {
        return true
    }
    else {
        return false
    }
}

Function Get_AAD_Server_Logins() {
    $tsql = @"
    SELECT name, type_desc, type, is_disabled 
    FROM sys.server_principals
    WHERE type_desc like 'external%' 
"@

    try {
        $sqlConn.open()

        $sqlCommand = $sqlConn.CreateCommand()
        $sqlCommand.CommandText = $tsql

        $datatable = new-object System.Data.DataTable
        $adapter = new-object System.Data.SqlClient.SqlDataAdapter($sqlCommand)

        $adapter.Fill($datatable)

        return $datatable
    }
    catch {
       $errMsg = $Error[0]
       Error "error at getting server logins, $errMsg" "Get_AAD_Server_Logins"
    }
    
}


SetupPrequisites

$serverLoginsTable = Get_AAD_Server_Logins

foreach ($Row in $serverLoginsTable.Rows)
{ 
  write-host "value is : $($Row[0])"
}

# Info "authenticated to AAD"

# Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $sql_server_resourcegroup `
# -ServerName $sql_server_name `
# -ObjectId $techpass_sqladmin_objectid `
# -DisplayName $techpass_sqladmin_username

#connect azsql
$sqlConnection = new-object System.Data.SqlClient.SqlConnection("Data Source=n9lxnyuzhv.database.windows.net; Initial Catalog=master;")
$sqlConnection.AccessToken = $accesstoken.Token
$sqlConnection.open()




# migrate for server-level logins


# migrate for db users
