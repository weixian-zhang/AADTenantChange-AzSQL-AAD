# Azure AD Tenant Change - Azure SQL Azure AD Enabled  

A PosH script to automate the restoration of Azure SQL and Azure SQL Managed Instance - Azure AD enabled sign-in, with Server Logins and Contained Database users, in an Azure subscription tenant change or SQL Server restoration situation

### Prerequisites

This script requires 3 environment variables to exist
| Env Var Name | Description |
| ------------- |:-------------:|
| azsqlaadm_aad_sqladmin_username | Azure AD SQL Admin username (set in Azure SQL Azure Active Directory blade) |
| azsqlaadm_aad_sqladmin_password | Azure AD SQL Admin password (Azure AD password) |
| azsqlaadm_sqlserver_name | server name of Azure SQL or SQL Managed Instance |



