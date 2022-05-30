<# Get-Adinfo.psm1 Notes

Was muss alles rein
#>

computer and server:

        getmac /FO LIST | findstr Phy
        list all ad computer, ip addr mac addr. dhcp lease
        list all ad server 
        list all ad computers in non default groups

            Get-ADComputer -Filter * -Properties * | Where-Object { 
                $_.MemberOf -like "**" 
            } | Select-Object Name,OperatingSystem,@{ 
                N="Grupper";E={ 
                    $groups="" 
                    $_.MemberOf |  get-adgroup | Select-Object Name | ForEach-Object {$groups+=$_.Name+","} 
                    $groups -replace ",$","" 
                    } 
                } 

        installed updates
        installed software
        new software since 30, 60, 90 day
        last reboot. uptime
        last 50 errors in event log

#--------------------------------------------------------------------------
Netzwerk :

        Get all dhcp leases

        Get-DhcpServerv4Lease -ComputerName vwdc.aab.vwz -ScopeID 10.10.0.0

        alle reservicerungen

        Get-DhcpServerv4Reservation -ComputerName vwdc.aab.vwz -ScopeID 10.10.0.0

get all connected users of a network printShareName

Get-WmiObject Win32_ServerConnection -ComputerName vwfile | Select-Object ShareName,UserName,ComputerName | Where-Object {$_.ShareName -eq "xxx"}

#--------------------------------------------------------------------------
Printer:

Get-Printer | ? published -eq $true

https://devblogs.microsoft.com/scripting/weekend-scripter-easily-publish-all-printers-on-a-print-server-to-active-directory/

Get-Printers -status "All" -errorlog -client "OK" -solution "FIN" -Verbose | Select-Object 'Environment', 'Logical name', 'Server name', 'Name', 'Location', 'Job count since last reset', 'Status', 'Printer status', 'Printer state', 'Detected error state', 'Extended detected error state', 'Extended printer status', 'Port name', 'Driver name', 'Network', 'Shared', 'Share name', 'Spool enabled', 'Work offline', 'Default', 'IP', 'Collected' | Out-GridView
Copy

https://www.improvescripting.com/how-to-list-installed-printers-using-powershell/

#--------------------------------------------------------------------------
