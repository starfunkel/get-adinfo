# Get-ADInfo

## Get-ADInfo is a CLI-only information gathering tool for Active Directory enviroments

***

### Usage

```
[PS] c:\ get-adinfo

        ==============================================================================================================================
        ||       _______________    ___   ___  _____  __________        ||                                                          ||
        ||      / ___/ __/_  ______/ _ | / _ \/  _/ |/ / __/ __ \       ||     Licence: GPL-3.0                                     ||
        ||     / (_ / _/  / / /___/ __ |/ // _/ //    / _// /_/ /       ||                                                          ||
        ||     \___/___/ /_/     /_/ |_/____/___/_/|_/_/  \____/        ||     Author: Starfunkel                                   ||
        ||                                                              ||                                                          ||
        ||        ACTIVE DIRECTORY Domain Services Section              ||                                                          ||
        ------------------------------------------------------------------------------------------------------------------------------
        ||           Forest | Domain | Domain Controller                ||                 Machine Discovery                        ||
        ------------------------------------------------------------------------------------------------------------------------------
        ||      1 - Forest | Domain | Sites Configuration               ||      14 - List all Windows Clients                       || 
        ||      2 - List Domain Controller                              ||      15 - List all Windows Server                        ||                    
        ||      3 - Show Default Domain Password Policy                 ||      16 - List all Computers (by Operatingsystem)        ||
        ||      4 - List Domain Admins                                  ||                                                          ||                        
        ------------------------------------------------------------------ ---------------------------------------------------------||
        ||                      GPMC MGMT                               ||                  VmWare                                  ||
        ----------------------------------------------------------------------------------------------------------------------------||    
        ||      5 - List all OUs                                        ||      17 - List all currently connected users on VSCs     ||
        ||      6 - List of Active GPOs and their Links                 ||      18 - List detailed information about VMs            ||
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

        Select
```

### To Do

#### AD Stuff

- list all ad computer, ip addr mac addr. dhcp lease
- list all ad server
- list all ad computers in non default groups
- installed updates
- installed software
- new software since 30, 60, 90 day
- last reboot. uptime
- last 50 errors in event log
