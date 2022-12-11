
--per database perform following

-- create user
CREATE USER [db-level-user-3@azworkbench.onmicrosoft.com] FROM EXTERNAL PROVIDER -- user exist already just for setting up to test only

-- alter the roles
ALTER ROLE [db_owner] ADD MEMBER [db-level-user-2@azworkbench.onmicrosoft.com]
ALTER ROLE [db_datawriter] ADD MEMBER [db-level-user-3@azworkbench.onmicrosoft.com]
ALTER ROLE [db_datareader] ADD MEMBER [db-level-user-3@azworkbench.onmicrosoft.com]


-- grant back permissions
GRANT CONNECT to [db-level-user-3@azworkbench.onmicrosoft.com]

--select database_role_members.role_principal_id, database_role_members.member_principal_id, 
select 
	coalesce(sys.database_principals.name, '') as [Role], 
	members.name as name, 
	--members.sid as sid, 
	coalesce(perms.permission_name, '') as [permission]
	--RIGHT(CONVERT(NVARCHAR(1000), members.sid, 2), 4) as AADExternalLogin
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

-- SELECT    roles.principal_id                            AS RolePrincipalID
-- 	,    roles.name                                    AS RolePrincipalName
-- 	,    database_role_members.member_principal_id    AS MemberPrincipalID
-- 	,    members.name                                AS MemberPrincipalName
-- 	, perms.permission_name
-- 	, members.type_desc as MemberType
-- FROM sys.database_role_members AS database_role_members
-- JOIN sys.database_principals AS roles  
-- 	ON database_role_members.role_principal_id = roles.principal_id  
-- JOIN sys.database_principals AS members  
-- 	ON database_role_members.member_principal_id = members.principal_id
-- LEFT JOIN (SELECT
-- 		class_desc
-- 		, CASE WHEN class = 0 THEN DB_NAME()
-- 			    WHEN class = 1 THEN OBJECT_NAME(major_id)
-- 			    WHEN class = 3 THEN SCHEMA_NAME(major_id) END [Securable]
-- 		, USER_NAME(grantee_principal_id) [AADUser]
-- 		, permission_name
-- 		, state_desc
-- 		FROM sys.database_permissions) perms
-- 	ON perms.[AADUser] = members.name
-- WHERE members.type_desc like 'external%'