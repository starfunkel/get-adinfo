#requires -version 5.1
# requires -module GroupPolicy,ActiveDirectory,VMware.VimAutomation.HorizonView

function Get-AdInfo{

    
    if (Get-Module -ListAvailable -Name ActiveDirectory) { ## Start RSAT check
        Import-Module ActiveDirectory
    } else { ## Install RSAT
        ""
        Write-Host "RSAT Moduls have to be installed first" -ForegroundColor Red
        Get-WindowsCapability -Name RSAT* -Online |
        Add-WindowsCapability -Online
        ""    
    } 
    
    <#
    if (Get-Module -Listavailable -name VMware.Vim* ) { ## Start VMware Automation Check
        Import-Module  VMware.VimAutomation.HorizonView 
    } else { ## Install Vmware.VimAutomation.HorizonView
        ""
        Write-Host "VMware Vi Automation Modul muss zuerst installiert werden"
        Install-Module -Name VMware.VimAutomation.HorizonView
        Import-Module -Name VMware.VimAutomation.HorizonView
        #  +++++ Vi Server Anmeldung + Zertifikatscheck aus + Kein Participation
        set-PowerCLIConfiguration -scope user -ParticipateinCEIP $false -Confirm:$false | Out-Null
        set-PowerCLIConfiguration -invalidcertificateaction  ignore -Confirm:$false | Out-Null 
        Clear-Host
        ""
    } ## VMware Vi Automation check
    #>
    
    do {
    
        function MENU {
    
        $WELCOME = @"
        ==============================================================================================================================
        ||       _______________    ___   ___  _____  __________        ||                                                          ||
        ||      / ___/ __/_  ______/ _ | / _ \/  _/ |/ / __/ __ \       ||     Licence: GPL-3.0                                     ||
        ||     / (_ / _/  / / /___/ __ |/ // _/ //    / _// /_/ /       ||                                                          ||
        ||     \___/___/ /_/     /_/ |_/____/___/_/|_/_/  \____/        ||     Author: Christian Rathnau                            ||
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
"@
        
            Write-Host -ForegroundColor "yellow" $WELCOME
            Write-Host ""
        }
        
        MENU

        $input=Read-Host "        Select" 
        
        switch ($input) 
        { 
        
    ##########################################
    ## Forest | Domain | Domain Controller  ##
    ##########################################
        
            1 {  
                ""
                Write-Host -ForegroundColor Green "FOREST Configuration" 
            
                $get=Get-ADForest
                $forest+=New-Object -TypeName PSObject -Property ([ordered]@{
            
                    "Root Domain"=$get.RootDomain
                    "Forest Mode"=$get.ForestMode
                    "Domains"=$get.Domains -join ","
                    "Sites"=$get.Sites -join ","
                    }
                )
            
                $forest | Format-Table -AutoSize -Wrap
                
                Write-Host -ForegroundColor Green "DOMAIN Configuration" 
                
                Get-ADDomain | Format-Table DNSRoot, DomainMode, ComputersContainer, DomainSID -AutoSize -Wrap
                Write-Host -ForegroundColor Green "SITES Configuration"
                    
                    $GetSite = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
                    $Sites = @()
                    foreach ($Site in $GetSite) {
                            $Sites += New-Object -TypeName PSObject -Property (
                            @{
                                "SiteName"  = $site.Name
                                "SubNets" = $site.Subnets  -Join "`n"
                                "Servers" = $Site.Servers  -Join "`n"
                            }
                        )
                    }
                    $Sites |
                    Format-Table -AutoSize -Wrap
                    
                
                Write-Host -ForegroundColor Green "Enabled OPTIONAL FEATURES" 
                Get-ADOptionalFeature -Filter * | 
                Format-Table Name,RequiredDomainMode,RequiredForestMode -AutoSize -Wrap
                
                Read-Host "Press 0 or Enter to continue"
                
            } ##  List Forest | Domain | Sites Configuration
            
            2 {  
                $dcs=Get-ADDomainController -Filter * 
                $dccount=$dcs |
                Measure-Object |
                Select-Object -ExpandProperty count
                ""
                Write-Host -ForegroundColor Green "Active Directory Domain Controller ($env:userdnsdomain)" 
            
                
                $domdc=@()
            
                foreach ($dc in $dcs) {
                    $domdc += New-Object -TypeName PSObject -Property (
                
                        [ordered]@{
                        "Name" = $dc.Name
                        "IP Address" = $dc.IPv4Address
                        "OS" = $dc.OperatingSystem
                        "Site" = $dc.Site
                        "Global Catalog" = $dc.IsGlobalCatalog
                        "FSMO Roles" = $dc.OperationMasterRoles -join "," # -join "`n"
                        }
                    )
                }
                ""
                
                $domdc | Format-Table -AutoSize -Wrap
            
                Write-Host "Total Number: "$dccount"" -ForegroundColor Yellow
            
                ""
                $ping=Read-Host "Do you want to test connectivity (ping) to these Domain Controllers? (Y/N)"
            
                If ($ping -eq "Y") {
                foreach ($items in $dcs.Name) {
                    Test-Connection $items -Count 1 | Format-Table Address, IPv4Address, ReplySize, ResponseTime}
                    Read-Host "Press 0 and Enter to continue"
                }
                
                else {
                ""
                    Read-Host "Press 0 and Enter to continue"
                }
            
            } ##  List Domain Controller
            
            3 { 
                ""
                Write-Host -ForegroundColor Green "The Default Domain Policy is configured as follows:"`n 
                Get-ADDefaultDomainPasswordPolicy |
                Format-List ComplexityEnabled, LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled
                
                Read-Host "Press 0 and Enter to continue" 
                
            } ##  Show Default Domain Password Policy
            
            4 { 
                ""
                Write-Host -ForegroundColor Green "The following USER are member of the Domain Admins group:"`n
                
                Get-ADGroupMember -Identity Administratoren -Recursive |
                Get-ADUser -Properties *  |
                Select-Object SamAccountName, Displayname, Enabled, lastlogondate, LastBadpasswordAttempt, BadLogonCount, PasswordLastSet, PasswordNeverExpires, SID |
                Format-table SamAccountName, Displayname, Enabled, lastlogondate, LastBadpasswordAttempt, BadLogonCount, PasswordLastSet, PasswordNeverExpires, SID
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## List Details of Domain Admins
            
    ###############
    ## GPMC MGMT ##
    ###############
            
            5 { 
                ""
                Write-Host -ForegroundColor Green "The following OU's are present in ($env:userdnsdomain)"
                Get-ADOrganizationalUnit -Filter * -Properties name, objectguid, description |
                Format-table name, objectguid, description
                ""
                Read-Host "Press 0 and Enter to continue"
            
            } ## List all OU"s
            
            6 { 
                ""
                Write-Host -ForegroundColor Green "List of all GPOs, their links and state:"`n 
                (Get-ADOrganizationalUnit -filter * | Get-GPInheritance).GpoLinks | 
                Select-Object -Property Target,DisplayName,Enabled,Enforced,Order |
                Format-Table
                ""
                Read-Host "Press 0 and Enter to continue"
            
            } ## Get GPOs and Links
            
    ###################
    ## User | Groups ##
    ###################
            
            7 {
                ""
                Write-Host -ForegroundColor Green "The Followeing Users are present in ($env:userdnsdomain)"
                ""
                Get-ADUser -Filter * -Properties Displayname, Enabled, lastlogondate, LastBadpasswordAttempt, BadLogonCount, PasswordLastSet, PasswordNeverExpires  |
                Sort-Object Name -Descending |
                Format-table Name, Displayname, Enabled, lastlogondate, LastBadpasswordAttempt, lastlogondate, PasswordLastSet, PasswordNeverExpires 
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## Shows all AD Users which are active, with their pw last set, and who are active
            
            8 { 
                ""
                Write-Host -ForegroundColor Green "The Following Users are disabled in ($env:userdnsdomain) (lastlogon sorting)"
                ""
                Get-ADUser -Filter {Enabled -eq $false} -Properties samaccountname, Name, lastlogondate, LastBadpasswordAttempt, PasswordLastSet |
                Sort-Object LastLogonDate |
                Format-Table samaccountname, Name, lastlogondate, LastBadpasswordAttempt, PasswordLastSet
                # start-sleep 1
                ""    
                Read-Host "Press 0 and Enter to continue"
            } ## Show all disabled AD Users
            
            9 {
                ""
                Write-Host -ForegroundColor Green "Enter a value in days for searching orphaned USER accounts"
                
                $time=Read-Host "How many days do you want to go back? (Press Q to escape )"
            
                If ($time -eq "Q")
                {Break}
                Write-Host  ""
                Write-Host -ForegroundColor Green "The following USERS are enabled and have not logged on for $time days:"
            
                Get-ADUser -Filter {enabled -eq $false} -Properties LastLogonDate |
                Where-Object {$_.lastlogondate -ne $null -and $_.lastlogondate -le ((get-date).adddays(-$time))} |
                Sort-Object -Property LastLogonDate -Descending |
                Format-Table Name,SamAccountName,LastLogonDate -AutoSize 
                
                
                Write-Host "User and Computer Logons are replicated every 14 days. Data might be not completely up-to-date." -ForegroundColor Yellow
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## Select time and show lastlogon time of Users
            
            10 {
                do {
                    ""
                    $userp=Read-Host "Enter user logon name"
                    ""
                    Write-Host "Details of user $userp" -ForegroundColor Green
                    
                    Get-ADUser $userp -Properties * |
                    Format-List GivenName,SurName,DistinguishedName,Enabled,EmailAddress,ProfilePath,ScriptPath,MemberOf,LastLogonDate,whencreated
                    $inputs=Read-Host "Quit searching users? (Y/N)"
                    }
                while ($inputs -eq "N")
            
            } ## Select and list USER Properties
            
            11 {
                ""
                Write-Host -ForegroundColor Green "Enter the USER name to display it's GRP memberships"
                ""
                $user=Read-Host "Username (Press Q to escape)"
            
                if ($user -eq "Q")
                {break}
                ""
                Write-Host -ForegroundColor Green "Group memberships of User $user "
                ""
                start-sleep 1
                get-adprincipalgroupmembership -Identity $user |
                Select-Object name, SID, distinguishedName |
                Sort-Object name
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## Show Group Memberships of given user
            
            12 {
                ""
                Write-Host -ForegroundColor Green "The following custom build global security groups are present in ($env:userdnsdomain)`n Note: all Builtin, and Schema groups are excluded from this view."
                ""
                Get-ADGroup -Filter {GroupScope -eq "Global" -and DistinguishedName -ne "*Builtin*" -and objectcategory -ne "Schema"}  -Properties name |
                Sort-Object -Property @{Expression = "name"; Descending = $false}  |
                Format-Table name, DistinguishedName, SID
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## List all global groups without Bultin and Schema Properties
            
            13 {
                ""
                Write-Host -ForegroundColor Green "Enter a group name to list all its members"
                ""
                $group=Read-Host "Group name (Press Q to escape)"
                
                if($group -eq "Q")
                {break}
                ""
                Write-Host -ForegroundColor Green "Group memebrs of $group"
                ""
                start-sleep 1  #### DEBUG !!!!!
                Get-ADGroupMember $group |
                Select-Object name, SID, distinguishedName
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## Select and list memebers of group
            
   
    #######################
    ## Machine Discovery ##
    #######################
            
            14 {
                ""
                Write-Host -ForegroundColor Green "AD joined Windows Clients $env:userdnsdomain"
                $client=Get-ADComputer -Filter {operatingsystem -notlike "*server*"} -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address 
                $ccount=$client | 
                Measure-Object | 
                Select-Object -ExpandProperty count
                ''
                Write-Output $client |
                Sort-Object Operatingsystem |
                Format-Table Name,Operatingsystem,OperatingSystemVersion,IPv4Address -AutoSize
                ""
                Write-Host "Total: "$ccount"" -ForegroundColor Yellow
                ""
                Read-Host "Press 0 and Enter to continue"

                ## Evtl. Mit Test Open Port Service Discovery

            } ## List all Windows Clients
            
            15 {
                ""
                Write-Host -ForegroundColor Green "Windows Server $env:userdnsdomain" 
                $server=Get-ADComputer -Filter {operatingsystem -like "*server*"} -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address 
                $scount=$server | 
                Measure-Object | 
                Select-Object -ExpandProperty count
                ""
                Write-Output $server |
                Sort-Object Operatingsystem |
                Format-Table Name,Operatingsystem,OperatingSystemVersion,IPv4Address
                ""
                Write-Host "Total: "$scount"" -ForegroundColor Yellow
                ""
                Read-Host "Press 0 and Enter to continue"
            } ##  List all Windows Server
            
            16 {
                ""
                Write-Host -ForegroundColor Green "All Computer $env:userdnsdomain" 
                $all=Get-ADComputer -Filter * -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address 
                $acount=$all | Measure-Object | Select-Object -ExpandProperty count
                ""
                Write-Output $all |
                Select-Object Name,Operatingsystem,OperatingSystemVersion,IPv4Address |
                Sort-Object OperatingSystem |
                Format-Table -GroupBy OperatingSystem 
                Write-Host "Total: "$acount"" -ForegroundColor Yellow
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## List all Computers

    ############
    ## VmWare ##
    ############

            17 {
                # https://communities.vmware.com/t5/VMware-PowerCLI-Discussions/PowerCLI-List-All-View-Connected-Users-and-VM-HostNames/td-p/970892
                ""
                Write-Host -ForegroundColor Green "Please enter a Horizon View Server to which you want to connect"
                $hvsrv=Read-Host "Please enter the IP Adress"
                ""
                Write-Host -ForegroundColor Green "The following USERs are currently connect to VMs"
            
                Import-Module -Name VMware.VimAutomation.HorizonView
                connect-hvserver $hvsrv    
            
                $query = New-Object "Vmware.Hv.QueryDefinition"
                $query.queryEntityType = "SessionLocalSummaryView"
                $qSrv = New-Object "Vmware.Hv.QueryServiceService"
                $qSRv.QueryService_Query($global:DefaultHVServers[0].ExtensionData,$query) |
                Select-Object -ExpandProperty Results |
                Select-Object -ExpandProperty NamesData |
                Select-Object -Property UserName,DesktopType,DesktopName,MachineOrRDSServerDNS |
                Sort-Object name |
                format-table
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## List all currently connected USERs to a given Horizon View Server
            
            18 {
                ""
                Write-Hoist -ForegroundColor Green "Please enter a VCenter Server to which you want to connect"
                $visrv=Read-Host "Please enter the Ip Adress"
                Write-Host -ForegroundColor Green "VM statistics of all Vms running on $visrv"
            
                Connect-VIServer $visrv
                $vms=get-vm
                Get-VMInformation $vms -ErrorAction SilentlyContinue|
                Format-Table -AutoSize
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## List detailed statistics about VMs
    


    ##################
    ## AD Comnputer ##
    ##################
            
            19 {
                do {
            
                    Write-Host ""
                    Write-Host "This runs systeminfo on specific computers. Select scope:" -ForegroundColor Green
                    Write-Host ""
                    Write-Host "1 - Localhost" -ForegroundColor Yellow
                    Write-Host "2 - Remote Computer (Enter Computername)" -ForegroundColor Yellow
                    Write-Host "3 - All Windows Server" -ForegroundColor Yellow
                    Write-Host "4 - All Windows Computer" -ForegroundColor Yellow
                    Write-Host "0 - Quit" -ForegroundColor Yellow
                    Write-Host ""
                    $scope=Read-Host "Select"
                    
                    $header="Host Name","OS","Version","Manufacturer","Configuration","Build Type","Registered Owner","Registered Organization","Product ID","Install Date","Boot Time","System Manufacturer","Model","Type","Processor","Bios","Windows Directory","System Directory","Boot Device","Language","Keyboard","Time Zone","Total Physical Memory","Available Physical Memory","Virtual Memory","Virtual Memory Available","Virtual Memory in Use","Page File","Domain","Logon Server","Hotfix","Network Card"
            
            
                    switch ($scope) {
            
                        1 {
                            
                            & "$env:windir\system32\systeminfo.exe" /FO CSV | Select-Object -Skip 1 | ConvertFrom-Csv -Header $header | Out-Host
                            
                        } ## Localhost
            
                        2 {
                            ""
                            Write-Host "Separate multiple computernames by comma. (example: server01,server02)" -ForegroundColor Yellow
                            Write-Host ""
                            $comps=Read-Host "Enter computername"
                            $comps=$comps.Split(",")
            
                            $cred=Get-Credential -Message "Enter Username and Password of a Member of the Domain Admins Group"
                            Invoke-Command -ComputerName $comps -Credential $cred {systeminfo /FO CSV | Select-Object -Skip 1} -ErrorAction SilentlyContinue | ConvertFrom-Csv -Header $header | Out-Host
                            
            
                        } ## Remote Computer (Enter Computername)
            
                        3 { 
                            $cred=Get-Credential -Message "Enter Username and Password of a Member of the Domain Admins Group"
            
                            Invoke-Command -ComputerName (Get-ADComputer -Filter {operatingsystem -like "*server*"}).Name -Credential $cred {systeminfo /FO CSV | Select-Object -Skip 1} -ErrorAction SilentlyContinue | ConvertFrom-Csv -Header $header | Out-Host
                            
                        } ## All Windows Server
            
                        4 {
                            $cred=Get-Credential -Message "Enter Username and Password of a Member of the Domain Admins Group"
            
                            Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -Credential $cred {systeminfo /FO CSV | Select-Object -Skip 1} -ErrorAction SilentlyContinue | ConvertFrom-Csv -Header $header | Out-Host
                            
                        } ## All Windows Computer
            
                            } ## Ene SystemInfo Do Schleife 
                            
                }
                while ($scope -ne "0") ## Ende Auswahl Do Schleife
                        
            } ## Run Systeminfo on Remote Computers
            
            20 {
                ""
                Write-Host -ForegroundColor Green "Enter a COMPUTER name to list the installed software (CIM -> WinRM)"
                ""
                $softw=Read-Host "Computer name (Press q to escape)"
            
                if ($softw -eq "Q")
                {break}
                ""
                Get-CimInstance -ComputerName $softw -ClassName win32_product -ErrorAction SilentlyContinue | 
                Select-Object PSComputerName, Name, PackageName, InstallDate | 
                Sort-Object Name
                ""
                Read-Host "Press 0 and Enter to continue"
            } ## Get installed Software on remote Computer                                                                           ----->>>> geht das hier?
            
            20 {
                ""
                Write-Host -ForegroundColor Green "Enter a COMPUTER Name to list the USERs installed printers"
                ""
                $prnt=Read-Host "Computer name (Press Q to escape)"
            
                if($prnt -eq "Q")
                {break}
                ""
                Write-Host -ForegroundColor Green "These printers are installed on $prnt"
                ""
                Get-Service -ComputerName $prnt -Name RemoteRegistry | 
                Set-Service -StartupType Manual
            
                get-service -name RemoteRegistry -ComputerName $prnt |
                Set-Service -Status Running
            
                Get-UserNetPrinter -computerName $prnt
            
                get-service -name RemoteRegistry -ComputerName $prnt |
                Stop-Service -Force
                get-service -name RemoteRegistry -ComputerName $prnt |
                Set-Service -StartupType Disabled
                ""
            
                Read-Host "Press 0 and Enter to continue"
            } ## Get the installed Printers of a user 
            

        }
    }
    while ($input -ne "0")
}
        
       
    ######################
    ## Helper Functions ##
    ######################
    
    function Get-UserNetPrinter {
        
        [CmdletBinding()]
        PARAM(
            [Parameter(ValueFromPipelineByPropertyName = $true, Position = 0)]        
            [string[]]$computerName = $env:ComputerName
        )
        begin {
            #Return the script name when running verbose, makes it tidier
            write-verbose "===========Executing $($MyInvocation.InvocationName)==========="
            #Return the sent variables when running debug
            Write-Debug "BoundParams: $($MyInvocation.BoundParameters|Out-String)"
            $regexPrinter = "\\\\.*\\(.*)$"
            $regexPrinter2 =  "(\w*),"
            $regexPrinter3 = "\\\\.*\\(.*),winspool"
        }
        
        process {
            #Iterate through each computer passed to function
            foreach ($computer in $computerName) {
                ""
                write-verbose "Processing $computer"
                #Open the old remote registry
                $reglm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.Registryhive]::LocalMachine, $computer)
                $regu = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.Registryhive]::Users, $computer)
                #Grab the USER SIDS, try and ignore service accounts and stuff
                ""
                $sids = ($regu.GetSubKeyNames() | 
                    Where-Object {($_ -notlike "*.DEFAULT*") -and ($_ -notlike "*classes*") -and ($_.length -ge 9)})
                            
                    foreach ($sid in $sids) {
                        write-verbose "Processing UserSID:  $sid"
                        $printersReg = $regu.OpenSubKey("$sid\printers\connections")
                        $printerDefaultReg = $regu.OpenSubKey("$sid\printers\defaults")                             
                        ""
                        $DefaultPrinter = try {
                            ($regu.OpenSubKey("$sid\printers\defaults\$($printerDefaultReg.GetSubKeyNames())")).getvalue($null)} 
                            catch {$null}
                                if ($printerDefaultReg -eq $null){
                                    $printerDefaultReg = $regu.OpenSubKey("$sid\Software\Microsoft\Windows NT\CurrentVersion\Windows")  
                                    $DefaultPrinter = try {$printerDefaultReg.GetValue("Device")} catch {$null}
                                }
                                
                            Write-Verbose "Default Printer $DefaultPrinter"
                            if ($DefaultPrinter -match $regexPrinter3){
                                $DefaultPrinter = $Matches[1]
                            }
                            elseif ($DefaultPrinter -match $regexPrinter){
                                $DefaultPrinter = $Matches[1]
                            }
                            elseif ($DefaultPrinter -match $regexPrinter2){
                                $DefaultPrinter = $Matches[1]           
                            }
                            ""
                            if (($printersReg -ne $null) -and ($printersReg.length -gt 0)) {
                                $printers = $printersReg.getsubkeynames()
                                #Try and get the username from the SID - Need to be the same domain
                                #Should change to a try-catch for different domains
                                $user = $($(New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value)
            
                                    foreach ($printer in $printers) {
                                        #Need to split the regkey name to get proper values
                                        #Split 2 = Print server
                                        #Split 3 = printer name
                                        #Never seen a value in the 0 or 1 spots
                                        $split = $printer.split(",")
                                        $printerDetails = $regu.openSubKey("$SID\Printers\Connections\$printer")
                                        $printerGUID = $printerDetails.getValue("GuidPrinter")
                                        $spoolerPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\Servers\$($split[2])\Printers\$printerGUID\DsSpooler"
                                        $printSpooler = $reglm.OpenSubKey("$spoolerPath")
                
                                        #Make an object to store in the array
                                        $pdetails = [pscustomobject]@{
                                            computer         = $computer
                                            user             = $user
                                            printServer      = $split[2]
                                            printer          = $split[3]
                                            pringerGUID      = $printerGUID
                                            printerDesc      = $($printSpooler.getValue("description"))
                                            printerDriver    = $($printSpooler.getValue("DriverName"))
                                            printerLocation  = $($printSpooler.getValue("Location"))
                                            printerPortName  = $($printSpooler.getValue("PortName"))
                                            printerShareName = $($printSpooler.getValue("printShareName"))
                                            printerSpooling  = $($printSpooler.getValue("printSpooling"))
                                            printerPriority  = $($printSpooler.getValue("priority"))
                                            printerUNC       = $($printSpooler.getValue("uNCName"))
                                            printerDefault   = if ($split[3] -eq $DefaultPrinter){$true}
                                        }                       
                                        #Add the object to the array
                                        $pdetails
                                    }
                            }
                            else {
                                #Well, something didn"t work on this computer entry
                                #This script could do with better error handling
                                write-verbose "No Access or No Printers"
                            }
                        }
                    }
            }
    } ## Get installed Printers on Computers ## https://www.reddit.com/r/PowerShell/comments/6h3a93/how_to_list_off_the_default_printer_for_each_user/