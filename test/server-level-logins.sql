
--DECLARE @serverlogin INT;
--var user = [server-level-login-1@azworkbench.onmicrosoft.com]

SELECT name, type_desc, type, sid, 
LEFT(CONVERT(NVARCHAR(1000), sid, 2), LEN(CONVERT(NVARCHAR(1000), sid, 2))- 4 ), 
RIGHT(CONVERT(NVARCHAR(1000), sid, 2), 4) as AADExternalLogin
FROM sys.database_principals 
WHERE type_desc like 'external%' --AADE means this user is mapped to an AAD based server-login



-- loop thru result and run the following

	-- create server level login
	Use master
	CREATE LOGIN [aad-group-server-level-1] FROM EXTERNAL PROVIDER
	GO

	--assign server level role from above select statement
	ALTER SERVER ROLE ##MS_ServerStateReader##
	ADD MEMBER [aad-group-server-level-1];  
	GO


	-- create server-log for AAD Group
	-- create server level login
	Use master
	CREATE LOGIN [dbuser-map-serverlogin-sll1@azworkbench.onmicrosoft.com] FROM EXTERNAL PROVIDER
	GO

	--assign server level role from above select statement
	ALTER SERVER ROLE ##MS_ServerStateReader##
	ADD MEMBER [db-level-user-1@azworkbench.onmicrosoft.com];  
	GO


select * from sys.server_principals
SELECT * FROM [sys].sql_logins	

select l.name as [login name],u.name as [user name] from sysusers u inner join sys.sql_logins l on u.sid=l.sid









