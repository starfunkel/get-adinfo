# Get-ADInfo
***
##### Get-ADInfo ist ein reines CLI Tool zur schnellen Informationsbeschaffung in Windows Active Directory Netzwerken.

### Download  & Usage

> 1. Either download  manually or clone repo to prefered location.
> 2. Open Powershell, locate the get-ad.ps1 and dot source it to run
> 3. The Script is configured to check nad autoinstall Vmware Automation Powershell Modules as well as the RSAT Powershell Tools.  
#### Usage
 ``` 
c:\ get-adinfo

    =========================================================
        ACTIVE DIRECTORY Domain Services Section (v 0.5.3)
    =========================================================
    |          Forest | Domain | Domain Controller           |
    ----------------------------------------------------------
    | 1 - Forest | Domain | Sites Configuration              |
    |     For Domain (INTEGRATE-IT.DE)                       |
    | 2 - List Domain Controller                             |
    | 3 - Show Default Domain Password Policy                |
    | 4 - List Domain Admins                                 |
    ----------------------------------------------------------
    |                       GPMC MGMT                        |
    ----------------------------------------------------------
    | 5 - List all OUs                                       |
    | 6 - List of Active GPOs and their Links                |
    ----------------------------------------------------------
    |                     User | Groups                      |
    ----------------------------------------------------------
    | 7 - Show Active AD USER with PasswordLastSet Info      |
    | 8 - Show Disabled AD USER with last logon date         |
    | 9 - USERs last logon date filtered by time             |
    | 10 - Select and list USER Properties                   |
    | 11 - Show Group memberships of given USER              |
    | 12 - List all GROUPS without Builtin and Scheme GROUPS |
    | 13 - Select and list memebers of a GROUP               |
    ----------------------------------------------------------
    |                     VmWare                             |
    ----------------------------------------------------------
    | 14 - List all currently connected USERs                |
    | 15 - List detailed information about VMs               |
    | !!!  Note: This only works if the                      |
    | !!!  VMware.VimAutomation.HorizonView PowerCli Module  |
    | !!!  is installed.                                     |
    ----------------------------------------------------------
    |                  Machine Discovery                     |
    ----------------------------------------------------------
    | 16 - List all Windows Clients                          |
    | 17 - List all Windows Server                           |
    | 18 - List all Computers (by Operatingsystem)           |
    ---------------------------------------------------------
    |                   AD Computer                          |
    ---------------------------------------------------------
    | 19 - Run Systeminfo on Remote Computers                |
    | 20 - List all installed Software on remote Computer    |
    | 21 - Get the installed Printers of a user              |
    ---------------------------------------------------------
    |                OnBoarding | OffBoarding                |
    ---------------------------------------------------------
    Select:
 ```
   
> ### Future Plans
>
> Maybe I implement an on and offboarding feature
>
> Also worth mentioning is the difficulty of hybrid on-prem and cloud based active directory structures. 