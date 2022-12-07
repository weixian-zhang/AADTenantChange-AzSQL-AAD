
--DECLARE @serverlogin INT;
--var user = [server-level-login-1@azworkbench.onmicrosoft.com]

SELECT name, type_desc, type, is_disabled 
FROM sys.server_principals
WHERE type_desc like 'external%' 


SELECT
		member.principal_id                        AS MemberPrincipalID
	,        member.name                                        AS MemberPrincipalName
	,   member.sid                  AS memberSID
	,        roles.principal_id                        AS RolePrincipalID
	,        roles.name                                        AS RolePrincipalName
FROM sys.server_role_members AS server_role_members
INNER JOIN sys.server_principals        AS roles
	ON server_role_members.role_principal_id = roles.principal_id
INNER JOIN sys.server_principals        AS member 
ON server_role_members.member_principal_id = member.principal_id

-- loop thru result and run the following

	-- create server level login
	Use master
	CREATE LOGIN [server-level-login-1@azworkbench.onmicrosoft.com] FROM EXTERNAL PROVIDER
	GO

	--assign server level role from above select statement
	ALTER SERVER ROLE ##MS_ServerStateReader##
	ADD MEMBER [server-level-login-1@azworkbench.onmicrosoft.com];  
	GO




