############################################
# Customise C6M1 Servers for labs          #
############################################
# LON-SVR1 - 4 require 3x 32GB drives each #
################################################################################
# Still to be completed:                                                       #
#  - Multiple NICs as per lab 13                                               #
#  - Verify working properly and meets requirements of all labs                # 
################################################################################
# Enhancements should include                                                  #
#   - making sure Admininstrator's password does not expire                    #
#   - WDS installed and configured to deply Server and Windows 10              #                                                                              #
################################################################################
Set-Location 'P:\Scripts\Lab Setup'
$vhdloc = (get-vmhost).VirtualHardDiskPath

#Networks to be added - think the rename does not like spaces
# $Network1 = "Ethernet 2"
# $Network2 = "Ethernet 3"

# Script blocks required for renaming
$ScriptBlockRenameAdapter =
{
    foreach ($N in (Get-NetAdapterAdvancedProperty -DisplayName "Hyper-V Network Adapter Name" ))
    { 
    $N | Rename-NetAdapter -NewName $n.DisplayValue 
    }

}

#Passwords
$Password = 'P@ssw0rd'| ConvertTo-SecureString -AsPlainText -Force  # use as default password
$DomainPassword = 'Pa$$w0rd' | ConvertTo-SecureString -AsPlainText -Force
$LocalPassword = "P@ssw0rd" | ConvertTo-SecureString -AsPlainText -Force

#Users
$W10Admin = "localadmin"
$DomainAdmin = "$Domain\administrator"
$LocalServerAdmin = "Administrator"

#Actual Credentials
$localW10Cred = New-Object system.management.automation.PSCredential($W10Admin,$LocalPassword)
$LocalServerCred = New-Object system.management.automation.PSCredential($LocalServerAdmin,$LocalPassword)
$DomainCred = New-Object system.management.automation.PSCredential($DomainAdmin,$DomainPassword)

# ensure stopped
$vmstate = get-vm lon-svr*

# Test for additional switches for Labs 13 and 14
<#
foreach ($v in $Network1,$Network2) 
    {
    $Network = $v

    if (-not (Test-VMSwitchexistence $Network)) 
        {
        write-host "Creating " $network
        New-VMSwitch $Network -SwitchType Private
        }
      else
        {
        Write-Host $network "exists"
        }
    }
#>

foreach ($vm in $vmstate) 
    {
    $v = $vm.vmname
    
    # enable virtualisation on each server 
    if ($vm.state -ne "Off") {write-host "Stopping $v";stop-vm -VMName $v -Force}

    do 
        {
            write-host "Waiting 10 seconds..."
            Start-Sleep 10
        } while ((get-vm -vmname $vm.vmname).state -ne "Off")


    # Configure for nested virtualisation

    Set-VMProcessor -VMName $vm.vmname -ExposeVirtualizationExtensions $true
    Set-VMNetworkAdapter -VMName $vm.vmname -MacAddressSpoofing On 

    # Add extra drives for storage spaces (Lab ??)

    foreach ($drv in 1,2,3)
        {
            $hddpath = "$vhdloc\$v-drive$drv.vhdx"

            new-vhd -path $hddpath -SizeBytes 32GB -Dynamic
            Add-VMHardDiskDrive -VMName $vm.vmname -Path $hddpath
         }
<#
    # Add additional NICs for labs on HA
    Add-VMNetworkAdapter -VMName $vm.vmname -SwitchName $Network1
    Add-VMNetworkAdapter -VMName $vm.vmname -SwitchName $Network2

    # allows the Name to be seen internally aftyer restart
    Get-VMNetworkAdapter -VMName $Vm.VMName | Set-VMNetworkAdapter -DeviceNaming On 
    
    # Rename vnnetworkadapters (external) to switch names so can be read internally
    $VMSwitches = (Get-VMNetworkAdapter -VMName $VM.vmname).SwitchName
    foreach ($c in $VMSwitches) 
        {
            Get-VMNetworkAdapter -VMName $VM.VMName `
            | Where-Object SwitchName -EQ $C `
            | Rename-VMNetworkAdapter -NewName $C
        }
        

    #start VM so can configure it internally
    start-vm $vm.vmname

    #wait until up and running fully
    Wait-VM -VM $vm -For IPAddress
    $sess = New-PSSession -VMName $vm.VMName -Credential $DomainCred
    # Invoke-Command -Session $sess  $ScriptBlockRenameAdapter
    # assign IP addresses based on 
    # Cluster Network = 10.100.100.svr (Network1)
    # iSCSI Network = 10.200.200.svr (Network2)
    $ClusterIP = "10.100.100." + ($svr+2).ToString() 
    $DataIP = "10.200.200." + ($svr+2).ToString() 
    New-NetIPAddress -InterfaceAlias $Network1 -IPAddress $ClusterIP -PrefixLength 24
    New-NetIPAddress -InterfaceAlias $Network2 -IPAddress $DataIP -PrefixLength 24
 
    Remove-PSSession $sess
#>
    }