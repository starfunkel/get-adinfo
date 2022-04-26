# Get-ADInfo
##### Get-ADInfo is a CLI-only information gathering tool for Active Directory enviroments.
***
### Download & Usage

> 1. Either download manually or clone repo to prefered location.
> 2. Open Powershell and import module
***
### Usage
 `
c:\ get-adinfo


```´
==============================================================================================================================
||      _______________    ___   ___  _____  __________         ||                                                          ||
||    / ___/ __/_  ______/ _ | / _ \/  _/ |/ / __/ __ \         ||                                                          ||
||   / (_ / _/  / / /___/ __ |/ // _/ //    / _// /_/ /         ||                                                          ||
||   \___/___/ /_/     /_/ |_/____/___/_/|_/_/  \____/          ||                                                          ||
||                                                              ||                                                          ||
||        ACTIVE DIRECTORY Domain Services Section              ||                                                          ||
------------------------------------------------------------------------------------------------------------------------------
||           Forest | Domain | Domain Controller                ||                     VmWare                               ||
------------------------------------------------------------------------------------------------------------------------------
||        1 - Forest | Domain | Sites Configuration             ||     15 - List detailed information about VMs             || 
||            For Domain ($env:userdnsdomain)                               
||      2 - List Domain Controller                              ||                                                          ||                       
||      3 - Show Default Domain Password Policy                 ||                                                          ||
||      4 - List Domain Admins                                  ||------------------------------------------------------------                          
------------------------------------------------------------------                Machine Discovery                         ||
||                      GPMC MGMT                               ||----------------------------------------------------------||
-------------------------------------------------------------------     16 - List all Windows Clients                       ||
||      5 - List all OUs                                        ||      17 - List all Windows Server                        ||
||      6 - List of Active GPOs and their Links                 ||      18 - List all Computers (by Operatingsystem)        ||
------------------------------------------------------------------------------------------------------------------------------ 
||                    User | Groups                             ||                   AD Computer                            ||
------------------------------------------------------------------------------------------------------------------------------
||      7 - Show Active AD USER with PasswordLastSet Info       ||      19 - Run Systeminfo on Remote Computers             ||
||      8 - Show Disabled AD USER with last logon date          ||      20 - List all installed Software on remote Computer ||
||      9 - USERs last logon date filtered by time              ||      21 - Get the installed Printers of a user           ||
||      10 - Select and list USER Properties                    ||                                                          ||
||      11 - Show Group memberships of given USER               ||                                                          ||
||      12 - List all GROUPS without Builtin and Scheme GROUPS  ||                                                          ||
||      13 - Select and list memebers of a GROUP                ||                                                          ||
------------------------------------------------------------------------------------------------------------------------------

    Select:

