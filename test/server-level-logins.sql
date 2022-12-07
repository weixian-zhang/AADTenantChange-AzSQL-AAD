
--DECLARE @serverlogin INT;
--var user = [server-level-login-1@azworkbench.onmicrosoft.com]

SELECT name, type_desc, type, is_disabled 
FROM sys.server_principals
WHERE type_desc like 'external%' 



-- loop thru result and run the following

	-- create server level login
	Use master
	CREATE LOGIN [server-level-login-2@azworkbench.onmicrosoft.com] FROM EXTERNAL PROVIDER
	GO

	--assign server level role from above select statement
	ALTER SERVER ROLE ##MS_ServerStateReader##
	ADD MEMBER [server-level-login-2@azworkbench.onmicrosoft.com];  
	GO




