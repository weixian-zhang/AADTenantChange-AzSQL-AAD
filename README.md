# Azure AD Tenant Change - Azure SQL Azure AD Enabled  

A PosH script to automate the restoration of Azure SQL and Azure SQL Managed Instance - Azure AD enabled sign-in, with Server Logins and Contained Database users, in an Azure subscription tenant change or SQL Server restoration situation

### What this script does  

This script drops and recreates Server Logins and Database Contained Users after Azure SQL or SQL Managed Instance goes through an [AAD tenant change in subscription](https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription).  
Existing Azure AD that were added to SQL Server will not be able to login as the tenant domain name could be different from the "old tenant".
This script aims to solve this problem by dropping and recreating all server-logins and DB users, and remap users' roles and permission.

### Prerequisites

This script requires 3 environment variables to exist
| Env Var Name | Description |
| ------------- |:-------------:|
| azsqlaadm_aad_sqladmin_username | Azure AD SQL Admin username (set in Azure SQL Azure Active Directory blade) |
| azsqlaadm_aad_sqladmin_password | Azure AD SQL Admin password (Azure AD password) |
| azsqlaadm_sqlserver_name | server name of Azure SQL or SQL Managed Instance |



