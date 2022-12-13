#### helpers ####

Function SetupPrequisites() {

    try {

        
        
        #$global:appinsights = ""
        
        $global:aad_sqladmin_username = (Get-ChildItem env:azsqlaadm_aad_sqladmin_username).Value
        $global:aad_sqladmin_password = (Get-ChildItem env:azsqlaadm_aad_sqladmin_password).Value
        $global:sql_server_name = (Get-ChildItem env:azsqlaadm_sqlserver_name).Value

        # try {

        #     $aad_appinsights_key = (Get-ChildItem env:azsqlaadm_appinsights_key).Value

        #     if ($null -ne $aad_appinsights_key) {

        #         Info "AppInsights key detected in env var 'azsqlaadm_appinsights_key' "

        #         Info "locating .\Microsoft.ApplicationInsights.dll, in same directory as this script"

        #         Add-Type -Path ".\Microsoft.ApplicationInsights.dll"  

        #         Info "Microsoft.ApplicationInsights.dll added"

        #         $global:appinsights = [Microsoft.ApplicationInsights.TelemetryClient]::new()
        #         $global:appinsights.InstrumentationKey = $aad_appinsights_key
        #         $global:appinsights.Context.User.Id = $global:aad_sqladmin_username

        #         Info "Initialized App Insights client with key $aad_appinsights_key"

        #     } else{
        #         Warn "App Insights instrumentation key not found in env vars, skipping App Insights module and continue processing"
        #     }
        # }
        # catch {
        #     Error "" "SetupPrequisites"
        # }

        Info @"
        loaded env variables:
          -azsqlaadm_aad_sqladmin_username $aad_sqladmin_username
          -azsqlaadm_sqlserver_name $sql_server_name
"@

    }
    catch {
        Error "error when setting up prerequisites" "SetupPrequisites"
        exit
    }
}

Function Info($msg) {
    $now = NowStr
    Write-Host "[$now]: $msg" -fore blue
}

Function Warn($msg) {
    $now = NowStr
    Write-Host "[$now]: $msg" -fore Yellow
}


Function Success($msg) {
    $now = NowStr
    Write-Host "[$now]: $msg" -fore green
}

Function Error($msg, $source) {
    $now = NowStr
    $errMsg = "[$now]: ($source): $msg - {$_}"
    Write-Host $errMsg -fore red  
    
    if ($appinsights -ne "") {
        # $telemtryException = New-Object "Microsoft.ApplicationInsights.DataContracts.ExceptionTelemetry"  
        # $telemtryException.Exception = $_.Exception  
        $appinsights.TrackException($errMsg)
    }
}

Function NowStr() {
    return (get-date).ToLocalTime().ToString("dd-MM-yyyy HH:mm:ss")
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

Function Get_Databases() {
    try {

        $conn = Create_SQL_Connection "master" $aad_sqladmin_username $aad_sqladmin_password

        $dbTsql = "SELECT name FROM sys.databases"

        $conn.open()

        $sqlCommand = $conn.CreateCommand()
        $sqlCommand.CommandText = $dbTsql

        $dbNames = new-object System.Data.DataTable

        $adapter = new-object System.Data.SqlClient.SqlDataAdapter($sqlCommand)

        $adapter.Fill($dbNames)

        $conn.Close()

        return ,$dbNames
    }
    catch {
        Error "error when getting databases" "Get_Databases"
    }
    
}

Function DataTableHasRows($dt) {
    if($null -ne $dt -And $dt.Rows.Count -gt 0) {
        return $true
    } else {
        return $false
    }
}

Function Is_Server_Login_Exists($loginName) {
    

    try {

        $conn = Create_SQL_Connection 'master' $aad_sqladmin_username $aad_sqladmin_password

        $tsql = @"
        IF EXISTS (SELECT [name]
                FROM sys.server_principals
                WHERE 
					[name] = N'$loginName' and
					type_desc like 'external%')
        Begin
            select 1
        end
        ELSE
        BEGIN
            SELECT 0
        END
"@

        $sqlCmd = new-object System.Data.SqlClient.SqlCommand($tsql, $conn);

        $conn.open()

        $r = $sqlCmd.ExecuteScalar()

        $conn.Close()

        return $r
    }
    catch {
        Error "error when checking if server-login exists" "Is_Server_Login_Exists"
    }
}

Function Is_DB_User_Exist($database, $username) {
    

    try {

        $conn = Create_SQL_Connection $database $aad_sqladmin_username $aad_sqladmin_password

        $tsql = @"
        IF EXISTS (SELECT [name]
                FROM [sys].[database_principals]
                WHERE 
					[name] = N'$username' and
					type_desc like 'external%')
        Begin
            select 1
        end
        ELSE
        BEGIN
            SELECT 0
        END
"@

        $sqlCmd = new-object System.Data.SqlClient.SqlCommand($tsql, $conn);

        $conn.open()

        $r = $sqlCmd.ExecuteScalar()

        $conn.Close()

        return $r
    }
    catch {
        Error "error when checking if db user exists" "Is_DB_User_Exist"
    }
}

#### helpers ####


#### process db users with server logins ####


#already exists in the current database

Function Process_Server_Logins_and_Mapped_DB_Users() {

    try {

        Info "starting to recreate server-logins and DB users that mapped to server-logins"

        $dbUsersWithLogins = new-object System.Data.DataTable
        $dbUsersWithLogins.Columns.Add("database")
        $dbUsersWithLogins.Columns.Add("username")
        $dbUsersWithLogins.Columns.Add("role")
        $dbUsersWithLogins.Columns.Add("permission")
        $dbUsersWithLogins.Columns.Add("sid")
        $dbUsersWithLogins.Columns.Add("SIDWithoutAADE")
        $dbUsersWithLogins.Columns.Add("serverLoginName")
        
        Info "Retrieving databases"

        $dbs = Get_Databases

        Info "databases retrieved"

        foreach($row in $dbs.Rows) {

            $dbName = $row[0]

            Info "at database {$dbName}"
            
            $dbUsersServerLogins = Get_DB_Users_Roles_Permissions_With_Server_Logins $dbName

            foreach($row in $dbUsersServerLogins.Rows) {

                $role = $row[0]
                $username = $row[1]
                $permission = $row[2]
                $sid = $row[3]
                $sidWithoutAADE = $row[4]

                # important! - user to delete cannot be AAD SQL Admin when supporting recreating of users in Master db where
                # AAD SQL Admin also located in Master db
                if($aad_sqladmin_username -eq $userName) {
                    return      # return continue foreach loop
                }

                Info "DB user with SID {$sidWithoutAADE} finding matching server login"

                $serverLoginDT = Find_Server_Logins_By_DB_User_SID $sidWithoutAADE

                # this db user does have mapping to a server login
                if ($serverLoginDT.Count -ne "0") {

                    foreach($row in $serverLoginDT.Rows) {

                        $serverLoginName = $row[0]

                        Info "DB user {$username} with SID {$sidWithoutAADE} found matching server login {$serverLoginName}"

                        $newRow = $dbUsersWithLogins.NewRow()
                        $newRow.database = $dbName
                        $newRow.username = $username
                        $newRow.role = $role
                        $newRow.permission = $permission
                        $newRow.sid = $sid
                        $newRow.SIDWithoutAADE = $SIDWithoutAADE
                        $newRow.serverLoginName = $serverLoginName

                        $dbUsersWithLogins.Rows.Add($newRow)
                    }
                }
            }
        }

        foreach($row in $dbUsersWithLogins)
        {
            $database = $row[0]
            $username = $row[1]
            $role = $row[2]
            $permission = $row[3]
            $sid = $row[4]
            $SIDWithoutAADE = $row[5]
            $serverLoginName = $row[6]

            Info @"
            begin recreate server logins and remapping DB users with info:
                database: $database
                DB username: $username
                DB user role: $role
                DB user permission: $permission
                sid: $sid
                sid without AADE Suffix: $SIDWithoutAADE
                Server Login Name: $serverLoginName
"@

            if (Is_Server_Login_Exists $serverLoginName) {
                
                    Info "dropping server login {$serverLoginName} in master database"

                Drop_Server_Login $serverLoginName

                    Info "dropped server login {$serverLoginName} in master database"

                Create_Server_Login $serverLoginName

                if (Is_DB_User_Exist $database $username) {

                        Info "DB user $userName exists in database {$dbName}, begin re-creating user and adding appropriate roles and permissions to users"

                    Drop_DB_Contained_User $database $username

                        Info "DB user $userName dropped in database {$dbName}"

                    Create_DB_Users_FromServer_Login $database  $username $serverLoginName

                        Info "DB user $userName created in database {$dbName}"

                    if($role -ne "") {
                            Info "Roles {$role} detected for DB user {$userName} in database {$dbName}, adding role to user" 

                        Alter_Role_DB_User $dbname $role $userName
                    }else {
                        Info "No roles detected for DB user {$userName} in database {$dbName}"
                    }
                    
                    if($permission -ne "" -And $permission -ne "GRANT" -And $permission -ne "CONNECT") {
                            Info "Permission {$permission} detected for DB user $userName  database $dbName, adding permission to user" 

                        Grant_DB_User_Permissions $dbname $permission $userName
                    }else {
                        Warn "Ignore granting following permissions for DB user {$userName} ['GRANT', 'CONNECT', {no permission}] in database {$dbName}"
                    }
                }
            }            
        }

        Success "successfully recreated server-logins and DB users mapped to server-logins"
    }
    catch {
        Error "" "Process_Server_Logins_and_Mapped_DB_Users"
    }
}

Function Drop_Server_Login($loginName) {
    
    try {

        $conn = Create_SQL_Connection "master" $aad_sqladmin_username $aad_sqladmin_password

        $tsql = "DROP LOGIN [$loginName]"

        $sqlCmd = new-object System.Data.SqlClient.SqlCommand($tsql, $conn);

        $conn.open()

        $sqlCmd.ExecuteNonQuery()

        $conn.Close()
    }
    catch {
        $conn.Close()
        Error "error when creating server logins" "Create_Server_Login"
    }
}

Function Create_Server_Login($username) {

    try {

        $conn = Create_SQL_Connection "master" $aad_sqladmin_username $aad_sqladmin_password

        $tsql = "CREATE LOGIN [$username] FROM EXTERNAL PROVIDER"

        $sqlCmd = new-object System.Data.SqlClient.SqlCommand($tsql, $conn);

        $conn.open()

        $sqlCmd.ExecuteNonQuery()

        $conn.Close()
    }
    catch {
        $conn.Close()
        Error "error when creating server logins" "Create_Server_Login"
    }
    
}



Function Drop_DB_Contained_User($database, $username) {
    

    try {

        $conn = Create_SQL_Connection $database $aad_sqladmin_username $aad_sqladmin_password

        $tsql = "DROP USER [$username]"

        $sqlCmd = new-object System.Data.SqlClient.SqlCommand($tsql, $conn);

        $conn.open()

        $sqlCmd.ExecuteNonQuery()

        $conn.Close()
    }
    catch {
        $conn.Close()
        Error "error when creating server logins" "Create_Server_Login"
    }
}

Function Create_DB_Users_FromServer_Login($database, $username, $loginName) {

    try {

        $conn = Create_SQL_Connection $database $aad_sqladmin_username $aad_sqladmin_password

        $tsql = "CREATE USER [$username] FROM LOGIN [$loginName]"

        $sqlCmd = new-object System.Data.SqlClient.SqlCommand($tsql, $conn);

        $conn.open()

        $sqlCmd.ExecuteNonQuery()

        $conn.Close()
    }
    catch {
        $conn.Close()
        Error "error when creating server logins" "Create_Server_Login"
    }
}


Function Get_Server_Logins() {
    $tsql = @"
select name, sid, type_desc from sys.server_principals
WHERE type_desc like 'external%'
"@

    $conn = Create_SQL_Connection "master" $aad_sqladmin_username $aad_sqladmin_password

    $conn.Open()

    $sqlCommand = $conn.CreateCommand()
    $sqlCommand.CommandText = $tsql

    $datatable = new-object System.Data.DataTable

    $adapter = new-object System.Data.SqlClient.SqlDataAdapter($sqlCommand)

    $adapter.Fill($datatable)

    $conn.Close()

    return ,$datatable
}

Function Recreate_Server_Logins() {

    $serverLogins = Get_Server_Logins

    foreach($row in $serverLogins.Rows) {

        $name = $row[0]

        Drop_Server_Login $name
        
        # recreate server logins
        Create_Server_Login $name

    }
}

# TODO
Function Get_DB_Users_Roles_Permissions_With_Server_Logins($dbName) {

    $tsql = @"
    select 
        coalesce(sys.database_principals.name, '') as [Role], 
        members.name as name, 
        coalesce(perms.permission_name, '') as [permission],
        CONVERT(NVARCHAR(1000), members.sid, 2) as [SID],
        LEFT(CONVERT(NVARCHAR(1000), members.sid, 2), LEN(CONVERT(NVARCHAR(1000), members.sid, 2))- 4 ) as SIDWithoutAADE

        from sys.database_principals as members
        left join sys.database_role_members AS database_role_members
        on database_role_members.member_principal_id = members.principal_id
        left join sys.database_principals
        on sys.database_principals.principal_id = database_role_members.role_principal_id

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

        WHERE 
            members.type_desc like 'external%'  and
            members.name not in ('dbo') and
            RIGHT(CONVERT(NVARCHAR(1000), members.sid, 2), 4) = 'AADE'
"@

    try {

        $conn = Create_SQL_Connection $dbName $aad_sqladmin_username $aad_sqladmin_password

        $sqlCommand = $conn.CreateCommand()
        $sqlCommand.CommandText = $tsql

        $datatable = new-object System.Data.DataTable

        $adapter = new-object System.Data.SqlClient.SqlDataAdapter($sqlCommand)

        $adapter.Fill($datatable)

        $conn.Close()
        
        return ,$datatable
    }
    catch {
        Error "" "Get_DB_Users_Roles_Permissions_With_Server_Logins"
    }
}

Function Find_Server_Logins_By_DB_User_SID($sid) {

    $tsql = @"
    select * from
    (select name, CONVERT(NVARCHAR(1000), sid, 2) as sid, type_desc
    from sys.server_principals
    WHERE type_desc like 'external%') as t
    where t.sid = '$sid'
"@

    try {

        $conn = Create_SQL_Connection "master" $aad_sqladmin_username $aad_sqladmin_password

        $sqlCommand = $conn.CreateCommand()
        $sqlCommand.CommandText = $tsql

        $datatable = new-object System.Data.DataTable

        $adapter = new-object System.Data.SqlClient.SqlDataAdapter($sqlCommand)

        $adapter.Fill($datatable)

        $conn.Close()
        
        # only 1 record always
        return ,$datatable
    }
    catch {
        Error "error when getting databases" "Get_Databases"
    }
}

#### process db users with server logins ####


#### process db contained users

Function Process_Database_Contained_Users() {

    try {

        Info "begin recreating db contained users"

        Info "retrieving databases"

        $dbs = Get_Databases

        Info "retrieve databases complete"

        foreach($row in $dbs.Rows) {

            $dbName = $row[0]

            Info "at database {$dbName}"

            Info "retrieving db contained user users, roles and permissions 'with no match server-logins' "

            $dbUsers = Get_DB_Users_Roles_Permissions_Without_Server_Login($dbName)

            Info "Completed retrieval of db contained user users, roles and permissions 'with no match server-logins' "

            foreach($row in $dbUsers.Rows) {

                $role = $row[0]
                $userName = $row[1]
                $permission = $row[2]
                
                # important! - user to delete cannot be AAD SQL Admin when supporting recreating of users in Master db where
                # AAD SQL Admin also located in Master db
                if($aad_sqladmin_username -ne $userName) {

                    $exists = Is_DB_User_Exist $dbName $userName

                    if($exists -eq 1) {

                        Info "DB user $userName exists in database $dbName, begin re-creating user and adding appropriate roles and permissions to users"

                        Drop_DB_Contained_User $dbName $userName

                        Info "DB user $userName dropped in database $dbName"

                        Create_DB_Contained_User $dbName $userName

                        Info "DB user $userName created in database $dbName"
                        
                        if($role -ne "") {
                            Info "Roles {$role} detected for DB user $userName database $dbName, adding role to user" 

                            Alter_Role_DB_User $dbname $role $userName
                        }else {
                            Info "No roles detected for DB user in $userName database $dbName"
                        }
                        
                        if($permission -ne "" -And $permission -ne "GRANT" -And $permission -ne "CONNECT") {
                            Info "Permission {$permission} detected for DB user $userName  database $dbName, adding permission to user" 

                            Grant_DB_User_Permissions $dbname $permission $userName
                        }else {
                            Warn "Ignore granting following permissions for DB user {$userName} ['GRANT', 'CONNECT', {no permission}] in database {$dbName}"
                        }
                    }
                }
            }
        }

        Success "recreation of db contained users completed successfully"
    }
    catch {
        Error "error when processing db $userName, $errMsg in database $dbName" "Process_Database_Users"
    }
}

Function Get_DB_Users_Roles_Permissions_Without_Server_Login($dbName) {
    $userRPTSQL = @"
    select 
	coalesce(sys.database_principals.name, '') as [Role], 
	members.name as name, 
	coalesce(perms.permission_name, '') as [permission]

    from sys.database_principals as members
    left join sys.database_role_members AS database_role_members
    on database_role_members.member_principal_id = members.principal_id
    left join sys.database_principals
    on sys.database_principals.principal_id = database_role_members.role_principal_id

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

    WHERE 
        members.type_desc like 'external%'  and
        members.name not in ('dbo') and
        RIGHT(CONVERT(NVARCHAR(1000), members.sid, 2), 4) <> 'AADE'
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


Function Create_DB_Contained_User($dbname, $userName) {

    try {

       $tsql = @"

       CREATE USER [$userName] FROM EXTERNAL PROVIDER
"@

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
        Error "error when re-creating db contained user as external provider (AAD), $errMsg" "Create_DB_Contained_User"
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
        Error "error when re-creating db contained user as exterbal provider (AAD), $errMsg" "Alter_Role_DB_User"
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
        Error "error when granting permission to $userName at database [$dbname]" "Grant_DB_User_Permissions"
    }
}


SetupPrequisites

Test-SQLConnection "master" $aad_sqladmin_username $aad_sqladmin_password

Success "Azure AD SQL Admin $aad_sqladmin_username is able to connect to SQL Server $sql_server_name"

Process_Database_Contained_Users

Process_Server_Logins_and_Mapped_DB_Users

Success @"
Completed
    -remapping of contained DB users to Server-Logins
    -recreate contained DB users as Azure AD users
"@





### setup prerequisites ###

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


#$global:techpass_techpass_tenant_id = (Get-ChildItem env:azsqlaadm_techpass_tenant_id).Value
#$global:sql_server_resourcegroup = (Get-ChildItem env:azsqlaadm_rg).Value

# $aadADminPassword = ConvertTo-SecureString -AsPlainText -Force -String $aad_sqladmin_password 
# $azcred = New-Object System.Management.Automation.PSCredential $aad_sqladmin_username, $aadADminPassword

# login to Azure techpass tenant
# Info "authenticating to AAD"
# Connect-AzAccount -Credential $azcred -Tenant $techpass_techpass_tenant_id
# $global:accesstoken = Get-AzAccessToken

#$global:sqlConn = new-object System.Data.SqlClient.SqlConnection("Data Source=$sql_server_name; Authentication=Active Directory Password; Initial Catalog=master;  UID=$aad_sqladmin_username; PWD=$aad_sqladmin_password")
#$global:sqlConn.AccessToken = $accesstoken.Token

### setup prerequisites ###



### set AAD SQL admin in powershell, not in used now ###

# Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $sql_server_resourcegroup `
# -ServerName $sql_server_name `
# -ObjectId $techpass_sqladmin_objectid `
# -DisplayName $techpass_sqladmin_username

#connect azsql
# $sqlConnection = new-object System.Data.SqlClient.SqlConnection("Data Source=n9lxnyuzhv.database.windows.net; Initial Catalog=master;")
# $sqlConnection.AccessToken = $accesstoken.Token
# $sqlConnection.open()

### set AAD SQL admin in powershell, not in used now ###

