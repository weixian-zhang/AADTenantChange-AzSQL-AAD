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



#### helpers ####

Function SetupPrequisites() {


    try {
        

        #$global:techpass_techpass_tenant_id = (Get-ChildItem env:azsqlaadm_techpass_tenant_id).Value
        $global:aad_sqladmin_username = (Get-ChildItem env:azsqlaadm_aad_sqladmin_username).Value
        $global:aad_sqladmin_password = (Get-ChildItem env:azsqlaadm_aad_sqladmin_password).Value
        $global:sql_server_name = (Get-ChildItem env:azsqlaadm_sqlserver_name).Value
        #$global:sql_server_resourcegroup = (Get-ChildItem env:azsqlaadm_rg).Value

        # $aadADminPassword = ConvertTo-SecureString -AsPlainText -Force -String $aad_sqladmin_password 
        # $azcred = New-Object System.Management.Automation.PSCredential $aad_sqladmin_username, $aadADminPassword

        # login to Azure techpass tenant
        # Info "authenticating to AAD"
        # Connect-AzAccount -Credential $azcred -Tenant $techpass_techpass_tenant_id
        # $global:accesstoken = Get-AzAccessToken

        #$global:sqlConn = new-object System.Data.SqlClient.SqlConnection("Data Source=$sql_server_name; Authentication=Active Directory Password; Initial Catalog=master;  UID=$aad_sqladmin_username; PWD=$aad_sqladmin_password")
        #$global:sqlConn.AccessToken = $accesstoken.Token
    
    }
    catch {
        Error "error at setting up prerequisites" "SetupPrequisites"
        exit
    }
}

Function Info($msg) {
    Write-Host $msg -fore green
}
Function Error($msg, $source) {
    foreach($e in $Error){
        Write-Host "($source): $msg - {$e}" -fore red
    }
    
}

Function IsNullOrEmptyStr($str) {
    if ( $null -eq $str -Or [string]::IsNullOrEmpty($str)) {
        return true
    }
    else {
        return false
    }
}

Function Test-SQLConnection($dbName, $userName, $passw)
{    
    try
    {
        $conn = Create_SQL_Connection $dbName $userName $passw
        $conn.Open();
        $conn.Close();
    }
    catch
    {
        Error "test sql connection failed on sql server: $sql_server_name and username $userName" "Test-SQLConnection"
        exit
    }
}

Function Create_SQL_Connection($dbName, $userName, $passw) {
    $conn = new-object System.Data.SqlClient.SqlConnection("Data Source=$sql_server_name; Authentication=Active Directory Password; Initial Catalog=$dbName;  UID=$userName; PWD=$passw")
    return $conn
}


#### helpers ####


Function Create_Server_Login($username) {

    try {
        $tsql = "CREATE LOGIN [$username] FROM EXTERNAL PROVIDER"

        $sqlCmd = new-object System.Data.SqlClient.SqlCommand($tsql, $sqlConn);

        $sqlConn.open()

        $sqlCmd.ExecuteNonQuery()

        $sqlConn.Close()
    }
    catch {
        Error "error when creating server logins" "Create_Server_Login"
    }
    
}

Function Process_AAD_Server_Logins() {

    $tsql = "SELECT name, type_desc, type, is_disabled FROM sys.server_principals WHERE type_desc like 'external%'"

    try {
        $conn = Create_SQL_Connection "master" $aad_sqladmin_username $aad_sqladmin_password

        $conn.open()

        $sqlCommand = $conn.CreateCommand()
        $sqlCommand.CommandText = $tsql

        $datatable = new-object System.Data.DataTable

        $adapter = new-object System.Data.SqlClient.SqlDataAdapter($sqlCommand)

        $adapter.Fill($datatable)

        $sqlConn.Close()

        foreach($row in $datatable.Rows) {
            $name = $row[0]
            $typeDesc = $row[1]
            $type = $row[2]
            $is_disabled = $row[3]
        }
    }
    catch {
       Error "error at getting server logins" "Get_AAD_Server_Logins"
    }
}



Function Get_Databases() {
    try {
        $dbTsql = "SELECT name FROM sys.databases where name <> 'master'"
        $sqlConn.open()

        $sqlCommand = $sqlConn.CreateCommand()
        $sqlCommand.CommandText = $dbTsql

        $dbNames = new-object System.Data.DataTable

        $adapter = new-object System.Data.SqlClient.SqlDataAdapter($sqlCommand)

        $adapter.Fill($dbNames)

        $sqlConn.Close()

        return ,$dbNames
    }
    catch {
        Error "error when getting databases" "Get_Databases"
    }
    
}

Function Get_DB_Users_Roles_Permissions($dbName) {
    $userRPTSQL = @"
    SELECT    
	    roles.name                AS [Role]
	,   members.name              AS UserPrincipalName
	,   perms.permission_name     AS [Permissions]
	,   members.type_desc         AS MemberType
FROM sys.database_role_members AS database_role_members
JOIN sys.database_principals AS roles  
	ON database_role_members.role_principal_id = roles.principal_id  
JOIN sys.database_principals AS members  
	ON database_role_members.member_principal_id = members.principal_id
LEFT JOIN (SELECT
		class_desc
		, CASE WHEN class = 0 THEN DB_NAME()
			    WHEN class = 1 THEN OBJECT_NAME(major_id)
			    WHEN class = 3 THEN SCHEMA_NAME(major_id) END [Securable]
		, USER_NAME(grantee_principal_id) [AADUser]
		, permission_name
		, state_desc
		FROM sys.database_permissions) perms
	ON perms.[AADUser] = members.name
WHERE members.type_desc like 'external%' and members.name not in ('dbo')
"@

    try {
        $sqlConnection = Create_SQL_Connection $dbName $aad_sqladmin_username $aad_sqladmin_password #new-object System.Data.SqlClient.SqlConnection("Data Source=$sql_server_name; Authentication=Active Directory Password; Initial Catalog=$dbName;  UID=$aad_sqladmin_username; PWD=$aad_sqladmin_password")

        $sqlCommand = $sqlConnection.CreateCommand()
        $sqlCommand.CommandText = $userRPTSQL

        $datatable = new-object System.Data.DataTable

        $adapter = new-object System.Data.SqlClient.SqlDataAdapter($sqlCommand)

        $adapter.Fill($datatable)

        $sqlConnection.Close()
        
        return ,$datatable
    }
    catch {
        Error "error when getting databases" "Get_Databases"
    }
    
}

Function Recreate_DB_User_As_External_Provider($dbname, $userName) {

    try {

       $tsql = @"

       CREATE USER [$userName] FROM EXTERNAL PROVIDER
"@

#         $tsql = @"
        
#         IF NOT EXISTS (SELECT [name]
#         FROM [sys].[database_principals]
#         WHERE type_desc like 'external%' AND [name] = '$userName')
#         Begin
#             CREATE USER [$userName] FROM EXTERNAL PROVIDER
#         end
# "@

        $conn = Create_SQL_Connection $dbName $aad_sqladmin_username $aad_sqladmin_password

        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $tsql
        $paramUN = $cmd.Parameters.Add("@userName", [string]);
        $paramUN.Value = $userName

        $conn.Open()

        $cmd.ExecuteNonQuery()
        
        $conn.CLose()

    }
    catch {
        $errMsg = $Error[0]
        Error "error when re-creating db contained user as external provider (AAD), $errMsg" "Recreate_DB_User_As_External_Provider"
    }

}

Function Alter_Role_DB_User($dbname, $role, $userName) {

    try {
        $conn = Create_SQL_Connection $dbName $aad_sqladmin_username $aad_sqladmin_password

        $tsql = @"
    
        ALTER ROLE [$role] ADD MEMBER [$userName]
"@

        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $tsql

        $conn.Open()

        $cmd.ExecuteNonQuery()

        $conn.CLose()
    }
    catch {
        $errMsg = $Error[0]
        Error "error when re-creating db contained user as exterbal provider (AAD), $errMsg" "Recreate_DB_User_As_External_Provider"
    }
}

Function Grant_DB_User_Permissions($dbname, $permission, $userName) {

    try {
        $conn = Create_SQL_Connection $dbName $aad_sqladmin_username $aad_sqladmin_password

        $tsql = @"
    
        GRANT $permission to [$userName]
"@

        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $tsql

        $conn.Open()

        $cmd.ExecuteNonQuery()

        $conn.CLose()
    }
    catch {
        Error "error when re-creating db contained user as exterbal provider (AAD)" "Recreate_DB_User_As_External_Provider"
    }
}

Function Process_Database_Users() {

    try {

        $dbs = Get_Databases

        foreach($row in $dbs.Rows) {
            $dbName = $row[0]

            $dbUsers = Get_DB_Users_Roles_Permissions($dbName)

            foreach($row in $dbUsers.Rows) {
                $role = $row[0]
                $userName = $row[1]
                $permission = $row[2]
                $userType = $row[3]

                Recreate_DB_User_As_External_Provider $dbName $userName

                Alter_Role_DB_User $dbname $role $userName

                Grant_DB_User_Permissions $dbname $permission $userName
            }
        }
    }
    catch {
        $errMsg = $Error[0]
        Error "error when processing db users, $errMsg" "Process_Database_Users"
    }

    
}


SetupPrequisites

Test-SQLConnection "master" $aad_sqladmin_username $aad_sqladmin_password

Info "Azure AD SQL Admin $aad_sqladmin_username is able to connect to DB server $sql_server_name"
# Process_AAD_Server_Logins

Process_Database_Users

Info @"
Completed
    -remapping of contained DB users to Server-Logins
    -recreate contained DB users as Azure AD users
"@

# Info "authenticated to AAD"

# Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $sql_server_resourcegroup `
# -ServerName $sql_server_name `
# -ObjectId $techpass_sqladmin_objectid `
# -DisplayName $techpass_sqladmin_username

#connect azsql
# $sqlConnection = new-object System.Data.SqlClient.SqlConnection("Data Source=n9lxnyuzhv.database.windows.net; Initial Catalog=master;")
# $sqlConnection.AccessToken = $accesstoken.Token
# $sqlConnection.open()




# migrate for server-level logins
# remap user to login
#https://www.aip.im/2010/05/re-map-database-user-to-login-in-sql-server-after-restoring-or-attaching-database/#sthash.fbazv94Z.dpuf

# migrate for db users
