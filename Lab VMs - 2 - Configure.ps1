############################################################
#     Configure VMs created for use in 70 Series labs      #
############################################################

# read-host  Press ENTER to confirm that VMs have been created and are running

# Verify in Administrative environment
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

############################################################################################################
# This script is to create a lab environment that mimics, as much as possible, the 70-740 MOAC online labs.
# The process requires
#
#     1) Create VMs  (Currently using Create VM.ps1 - should modify to own version here)
#     2) Configure VMs (essentially where up to)
#     3) Customise VMs (Need to verify what is required for drives, NICs, etc)
#     4) Add required resources
#
# This is rough draft of a script and as yet, not very readable.
# Need to ensure that the regedit for autologon is finished

# set to stop if PowerShell cmdlet error occurs
$ErrorActionPreference = "Stop"

# Create details about each machine

$Domain = "Adatum"
$DomainFQDN = "Adatum.com"
  
$LON_DC1 = @{
 "VM" = "LON-DC1"
 "IP" = "172.16.0.10"
 "PrefixLength" = "24"
 "DNSServer" = "172.16.0.10"
 "DefaultGW" = "172.16.0.1"
}

$LON_RTR = @{
 "VM" = "LON-RTR"
 "IP" = "172.16.0.1"
 "PrefixLength" = "24"
 "DNSServer" = "172.16.0.10"
}


$LON_WDS1 = @{
 "VM" = "LON-WDS1"
 "IP" = "172.16.0.11"
 "PrefixLength" = "24"
 "DNSServer" = "172.16.0.10"
 "DefaultGW" = "172.16.0.1"
}

$LON_SVR1 = @{
 "VM" = "LON-SVR1"
 "IP" = "172.16.0.21"
 "PrefixLength" = "24"
 "DNSServer" = "172.16.0.10"
 "DefaultGW" = "172.16.0.1"
}

$LON_SVR2 = @{
 "VM" = "LON-SVR2"
 "IP" = "172.16.0.22"
 "PrefixLength" = "24"
 "DNSServer" = "172.16.0.10"
 "DefaultGW" = "172.16.0.1"
 }

$LON_SVR3 = @{
 "VM" = "LON-SVR3"
 "IP" = "172.16.0.23"
 "PrefixLength" = "24"
 "DNSServer" = "172.16.0.10"
 "DefaultGW" = "172.16.0.1"
 }

$LON_SVR4 = @{
 "VM" = "LON-SVR4"
 "IP" = "172.16.0.24"
 "PrefixLength" = "24"
 "DNSServer" = "172.16.0.10"
 "DefaultGW" = "172.16.0.1"
 }

 $LON_ADM1 = @{
 "VM" = "LON-ADM1"
 "IP" = "172.16.0.40"
 "PrefixLength" = "24"
 "DNSServer" = "172.16.0.10"
 "DefaultGW" = "172.16.0.1"
}


Function wait-VMBoot 
{
#
#  To pause script until a VM has completed booting - have to know what IP it will have once up and running
#
   param(
        [String]$VMName,
        [Int]$Wait
   )  
        write-host "Waiting for $VMName..." 
        if ((get-vm $VMName).state -ne 'Running') {Start-VM $VMName}
        $VM = get-vm $VMname
        wait-VM $VM -For IPAddress

}

# Host Specific varaibles for host
$Password = 'P@ssw0rd'| ConvertTo-SecureString -AsPlainText -Force  # use as default password
$DomainPassword = 'Pa$$w0rd' | ConvertTo-SecureString -AsPlainText -Force
$LocalPassword = "P@ssw0rd" | ConvertTo-SecureString -AsPlainText -Force
$W10Admin = "localadmin"
$DomainAdmin = "$Domain\administrator"
$LocalServerAdmin = "Administrator"

$localW10Cred = New-Object system.management.automation.PSCredential($W10Admin,$LocalPassword)
$LocalServerCred = New-Object system.management.automation.PSCredential($LocalServerAdmin,$LocalPassword)
$DomainCred = New-Object system.management.automation.PSCredential($DomainAdmin,$DomainPassword)

# Script Blocks used to configure VMs
$ScriptBlockContentIP =
{
    if ((get-netipaddress -interfacealias "Ethernet").IPAddress -ne $using:v.ip) {New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $using:v.IP -PrefixLength $using:v.PrefixLength -DefaultGateway $using:v.DefaultGW }
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $using:v.DNSServer
}
$ScriptBlockRenameComputer =
{
    if ((get-computerinfo).csname -ne $using:v.vm) 
        {
        Rename-Computer -NewName $using:v.VM -restart 
        }
}

$ScriptBlockContentDomainJoin = 
{
    add-computer -DomainName $using:DomainFQDN -DomainCredential $using:domaincred -NewName $using:v.VM -Restart 
}

$ScriptBlockConfigureFireWall = 
{
                Enable-PSRemoting
                get-netfirewallrule "*remote*" | Set-NetFirewallRule -Enabled True
                Get-NetFirewallRule FPS-ICMP*-ERQ-IN | Set-NetFirewallRule -Enabled True
                Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
}

$ScriptBlockContentDHCP = 
{
# configure DHCP server
    Install-WindowsFeature DHCP -IncludeManagementTools  
    $dhcpserver = $using:V.vm + "." + $using:domainfqdn
    Add-DhcpServerInDC -DnsName $dhcpserver -IPAddress $using:v.ip
    Add-DHCPServerSecurityGroup -ComputerName $dhcpserver
    Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2
    restart-service dhcpserver

# configure scope
    Add-DhcpServerv4Scope -name "$using:Domain" -StartRange 172.16.0.1 -EndRange 172.16.0.254 -SubnetMask 255.255.255.0 -State Active    
    Add-DhcpServerv4ExclusionRange -ScopeID 172.16.0.0 -StartRange 172.16.0.1 -EndRange 172.16.0.49
    Add-DhcpServerv4ExclusionRange -ScopeID 172.16.0.0 -StartRange 172.16.0.200 -EndRange 172.16.0.254
    Set-DhcpServerv4OptionValue -OptionID 3 -Value 172.16.0.1 -ScopeID 172.16.0.0 
    Set-DhcpServerv4OptionValue -DnsDomain $using:DomainFQDN -DnsServer 172.16.0.10

}

# A couple of general admin to disable autologon and enter AVMA key (should really put this in the autounattend script)

$ScriptBlockContentDisableAutoLogon =
{
     Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'-name "AutoAdminLogon" -Value 0 
}

$ScriptBlockContentSetAVMAKey =
{
    slmgr /ipk $Using:AVMAKey
}

$ScriptBlockClearAdminAutoLogon = 
{
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName"  -Value ""
}


# To install Windows Admin Center

$ScriptBlockInstallWindowsAdminCenter =
{
    $dlPath = "c:\users\administrator\downloads\WAC.msi"
    Invoke-WebRequest 'http://aka.ms/WACDownload' -OutFile $dlPath
    $port = 443
    msiexec /i $dlPath /qn /L*v log.txt SME_PORT=$port SSL_CERTIFICATE_OPTION=generate
}

# to chnage administrator password on DC1
$ScriptBlockResetAdministratorPassword =
{
    set-localuser -Name Administrator -password $using:DomainPassword   
}

# to verify DNS server is functioning - to be extended to a loop to wait until is working
$ScriptBlockTestDNSServer =
{
    Test-DNSServer -IPaddress 127.0.0.1 -ZoneName $using:DomainFQDN    
}

Function Create-Session
{
    param(
      $v,
      $Cred,
      $delay  )


wait-vmboot $v.vm -Wait $delay
write-host "Connecting to " $v.vm
$Time = [System.Diagnostics.Stopwatch]::StartNew()
$ElapsedTime = 0
do 
    {
    $s = New-PSSession -VMName $v.VM -Credential $Cred -ErrorAction SilentlyContinue
    if( -not $?) #No error returned
        {
            $msg = $error[0].Exception.Message
            if ($msg -eq "The credential is invalid.")
            {
                write-host "Invalid Credentials"
                break
            }
            else
            {
                write-host "Error other than invalid credentials" $msg " trying again - time passed: :" $time.Elapsed.Seconds
            }
        }    
    # quit if has been over five minutes
    $ElapsedTime = $ElapsedTime + $Time.Elapsed.Seconds
    if ($ElapsedTime -gt 300) {write-host "Timed out - last error " $error[0].ErrorDetails.Message ; break} else {write-host $ElapsedTime " seconds"}
    } while ($s.state -ne 'Opened')
    return $s
}


###############################################################
# Start actual configuration
###############################################################

# Create VMs
# need to be able to pass a list of VMs to be created to the script
# start-job -filepath $((get-location).path)\"create vm.ps1"
# at this stage have to enter details into vm.csv and run create vm script


# Configure LON-DC1
Function Configure-LONDC1
{

write-host "Configuring LON-DC1...."
$V = $LON_DC1

wait-VMBoot -VMName $v.VM
$sess = New-PSSession -VMName $v.VM -Credential $LocalServerCred

Invoke-Command -Session $sess $ScriptBlockClearAdminAutoLogon
Invoke-Command -Session $sess $ScriptBlockContentIP -ArgumentList ($V.IP,$V.PrefixLength,$V.DefaultGW,$V.DNSServer)
Invoke-Command -Session $sess $ScriptBlockRenameComputer -ArgumentList ($v.VM)

Remove-PSSession $sess


#Wait to complete restart
wait-vmboot -VMName $V.VM -wait 300

#Configure as Domain Controller
wait-vm -VMName $V.VM -For IPaddress
write-host "Configuring AD DS..."

## up to here in replacing connect
$sess = Create-Session -v $v $LocalServerCred 120

Invoke-Command -Session $sess { Set-LocalUser -Name Administrator -Password $Using:DomainPassword }
Invoke-Command -Session $sess { Install-WindowsFeature ad-domain-services -IncludeManagementTools }
Invoke-Command -Session $sess { Install-ADDSForest `
        -DomainName $using:DomainFQDN `
        -DomainNetbiosName $Using:Domain `
        -InstallDns:$true `
        -SafeModeAdministratorPassword $using:Password `
        -Force:$true } -ArgumentList  ($Domain, $DomainFQDN, $Password)
Remove-PSSession $sess

wait-vmboot -VMName $V.VM -wait 300
$sess = Create-Session $v $DomainCred 300

# Finish configuring DNS and add DHCP to DC1

write-host "Configuring DNS Zones and DHCP..."
# Confirm DNS installed
# add forward lookup zone - not sure what trying to do here because Zone already installed
# invoke-command -Session $sess -ScriptBlock { Add-DnsServerPrimaryZone -IPAddress $using:v.ip -ZoneName $using:DomainFQDN } -ArgumentList ($DomainFQDN, $v.ip)
# looks like need to add something to test DNS to ensure working

write-host "Sleeping for 300 seconds to ensure ready..." 
Start-Sleep -Seconds 300 # from time to time seems DNS is not fully function yet - give it a chance to fully configure 
invoke-command -session $sess $ScriptBlockTestDNSServer -argumentlist ($DomainFQDN)

# add rDNS zone
invoke-command -session $sess -scriptblock { add-DNSServerPrimaryZone -NetworkID "172.16.0.0/24" -ReplicationScope "Domain" }

# configure forwarder
Invoke-command -session $sess -scriptblock { Add-DnsServerForwarder -IPAddress 192.168.52.5 }

# configure DHCP
Invoke-command -Session $sess $ScriptBlockContentDHCP -ArgumentList ($DomainFQDN, $Domain, $V.ip)

Remove-PSSession $sess 
}

Function Configure-LONRTR
{
#Configure Router
write-host "Configuring LON-RTR......."
$v = $LON_RTR

$sess = Create-Session $v $LocalServerCred 120

Invoke-Command -Session $sess $ScriptBlockClearAdminAutoLogon
# not using scriptblock because no default gateway
Invoke-Command -Session $Sess {
    New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 172.16.0.1 -PrefixLength  24
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 172.16.0.10
    if (-not(test-connection $using:DomainFQDN)) {write-host "Cannot contact " $using:DomainFQDN | break}
    add-computer -DomainName $using:DomainFQDN -DomainCredential $using:domaincred -NewName LON-RTR -Restart
} -ArgumentList ($DomainFQDN,$DomainCred)
Remove-PSSession $sess

# wait while lon-rtr rebots after joining domain
$sess = Create-Session $v $DomainCred 120

#add 2nd (External) NIC
$E_Switch = Get-VMSwitch | where switchtype -eq "External"
Add-VMNetworkAdapter -VMName LON-RTR -SwitchName $E_Switch.Name


$sess = Create-Session $v $DomainCred 120

# rename adapters
write-host "Configuring NAT..."

Invoke-Command -Session $sess {
    Rename-NetAdapter -name "Ethernet" -NewName "LAN"
    Rename-NetAdapter -name "Ethernet 2" -NewName "WAN"
    }

#Install RRAS & Configure for NAT
Invoke-Command -Session $sess {

     Install-WindowsFeature Routing -IncludeManagementTools
     Install-RemoteAccess -VPNType VPN

     $ExternalInterface = "WAN"
     $InternalInterface = "LAN"

     cmd.exe /c "netsh routing ip nat install"
     cmd.exe /c "netsh routing ip nat add interface $ExternalInterface"
     cmd.exe /c "netsh routing ip nat set interface $ExternalInterface mode=full"
     cmd.exe /c "netsh routing ip nat add interface $InternalInterface"
     restart-computer -force
}
Remove-PSSession $sess
}

Function Configure-LONWDS1
{
write-host "Configuring LON-WDS1...."
$V = $LON_WDS1
wait-VMBoot -VMName $v.VM
$sess = New-PSSession -VMName $v.VM -Credential $LocalServerCred

Invoke-Command -Session $sess $ScriptBlockClearAdminAutoLogon
Invoke-Command -Session $sess $ScriptBlockConfigureFireWall
Invoke-Command -Session $sess $ScriptBlockContentIP -ArgumentList ($V.IP,$V.PrefixLength,$V.DefaultGW,$V.DNSServer)
Invoke-Command -Session $sess $ScriptBlockContentDomainJoin -ArgumentList ($DomainFQDN,$DomainCred,$v.VM)
Remove-PSSession $sess
}

Function Configure-LONSVR1
{
write-host "Configuring LON-SVR1...."
$V = $LON_SVR1
wait-VMBoot -VMName $v.VM
$sess = New-PSSession -VMName $v.VM -Credential $LocalServerCred

# Invoke-Command -Session $sess $ScriptBlockClearAdminAutoLogon
# Invoke-Command -Session $sess $ScriptBlockConfigureFireWall
# Invoke-Command -Session $sess $ScriptBlockContentIP -ArgumentList ($V.IP,$V.PrefixLength,$V.DefaultGW,$V.DNSServer)
Invoke-Command -Session $sess $ScriptBlockContentDomainJoin -ArgumentList ($DomainFQDN,$DomainCred,$v.VM)
Remove-PSSession $sess
}

Function Configure-LONSVR2
{
write-host "Configuring LON-SVR2...."
$V = $LON_SVR2
wait-VMBoot -VMName $v.VM
$sess = New-PSSession -VMName $v.VM -Credential $LocalServerCred

Invoke-Command -Session $sess $ScriptBlockClearAdminAutoLogon
Invoke-Command -Session $sess $ScriptBlockConfigureFireWall
Invoke-Command -Session $sess $ScriptBlockContentIP -ArgumentList ($V.IP,$V.PrefixLength,$V.DefaultGW,$V.DNSServer)
Invoke-Command -Session $sess $ScriptBlockContentDomainJoin -ArgumentList ($DomainFQDN,$DomainCred,$v.VM)
Remove-PSSession $sess
}

Function Configure-LONSVR3
{
write-host "Configuring LON-SVR3...."
$V = $LON_SVR3
wait-VMBoot -VMName $v.VM
$sess = New-PSSession -VMName $v.VM -Credential $LocalServerCred

Invoke-Command -Session $sess $ScriptBlockClearAdminAutoLogon
Invoke-Command -Session $sess $ScriptBlockConfigureFireWall
Invoke-Command -Session $sess $ScriptBlockContentIP -ArgumentList ($V.IP,$V.PrefixLength,$V.DefaultGW,$V.DNSServer)
Invoke-Command -Session $sess $ScriptBlockContentDomainJoin -ArgumentList ($DomainFQDN,$DomainCred,$v.VM)
Remove-PSSession $sess
}

Function Configure-LONSVR4
{
write-host "Configuring LON-SVR4...."
$V = $LON_SVR4
wait-VMBoot -VMName $v.VM
$sess = New-PSSession -VMName $v.VM -Credential $LocalServerCred

Invoke-Command -Session $sess $ScriptBlockClearAdminAutoLogon
Invoke-Command -Session $sess $ScriptBlockConfigureFireWall
Invoke-Command -Session $sess $ScriptBlockContentIP -ArgumentList ($V.IP,$V.PrefixLength,$V.DefaultGW,$V.DNSServer)
Invoke-Command -Session $sess $ScriptBlockContentDomainJoin -ArgumentList ($DomainFQDN,$DomainCred,$v.VM)
Remove-PSSession $sess
}
 

Function Configure-LONADM1
{
write-host "Configuring LON-ADM1...."
$V = $LON_ADM1
 
wait-VMBoot -VMName $v.VM
$sess = New-PSSession -VMName $v.VM -Credential $LocalW10Cred

Invoke-Command -Session $sess $ScriptBlockContentIP -ArgumentList ($V.IP,$V.PrefixLength,$V.DefaultGW,$V.DNSServer)
Invoke-Command -Session $sess $ScriptBlockContentDomainJoin -ArgumentList ($DomainFQDN,$DomainCred,$v.VM)
Remove-PSSession $sess


# start-sleep -s 300  - not sure why have 5 min sleep here 

wait-VMBoot -VMName $v.VM
$sess = New-PSSession -VMName $v.VM -Credential $DomainCred

# RSAT tools added in image 
# Customise the ADMIN workstation 

Invoke-Command -Session $sess -scriptblock {Get-WindowsCapability -Name RSAT* -online | Add-WindowsCapability -online}
Invoke-Command -Session $sess -ScriptBlock $ScriptBlockInstallWindowsAdminCenter
Remove-PSSession $sess
}

# The actual parts that run the code

# Configure-LONDC1
# Configure-LONRTR
# Configure-LONWDS1
Configure-LONSVR1
Configure-LONSVR2
Configure-LONSVR3
Configure-LONSVR4
# Configure-LONADM1