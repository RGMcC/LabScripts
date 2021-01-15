# Basic script to create VMs using syspreped VHDs

# Check in Admin mode

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

# set to stop if PowerShell cmdlet error occurs
$ErrorActionPreference = "Stop"

# Setup var for script folder
$ScriptFolder = 'P:\Scripts\Lab setup'

# Create hash table to hold information on each VM
$vms = import-csv 'Lab VMs.csv'

# check for existence of each network
write-host "Checking switches"

$switches = $vms | group-object -property Network | select Name

foreach ($v in $switches) 
    {
    $Network = $v.Name

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

##  Now to configure VMs

# Properties that will be associated with each VM are VMName, SourceVHD, VHDLoc, StartUpRam, Network

# Actually Create VMs
foreach ($v in $VMs)
    {
    # check to see if exists
    $exists = get-vm -name $v.vmname -ErrorAction SilentlyContinue
    if ($exists)
    {
        write-host $v.vmname "already exists"
    }
    else
    {
     if ((Select-String -InputObject ($v.RAM.ToLower()) -Pattern "gb") -ne $null) 
        { $StartUpRam = [Int64]($v.RAM).tolower().Replace('gb','')  * 1GB  } 
    elseif ((Select-String -InputObject ($v.RAM.tolower()) -Pattern "mb") -ne $null) 
        { $StartUpRam = [Int64]($v.RAM).tolower().Replace('mb','')  * 1MB  } 
    else
        { $StartUpRam = [int64]($v.ram) }
   Create-VM -VM $V.VMName `
			-BaseVHD $V.SourceVHD `
			-VHDLoc $V.VHDLoc `
			-Memory $StartUpRam `
			-Generation $v.Generation `
			-MemoryType $V.MemoryType `
			-Switch $V.Network `
			-DeploymentType $v.DeploymentType
    if ($v.SourceVHD -like '*W10*')
    {
        # if W10 Mount drive to copy unattend files
        $VHD = $v.VHDLoc + "\" + $v.VMName + ".vhdx"
        $DriveLetter = (Mount-VHD -Path $VHD  -PassThru | Get-Disk | Get-Partition | where {$_.Type -eq "Basic"} ).DriveLetter
        $dest1 = $Driveletter + ":\unattend.xml"
        $dest2 = $Driveletter + ":\autounattend.xml"
        $sourceXML1 = "$ScriptFolder\UnattendSettings.xml"
        $sourceXML2 = "$ScriptFolder\AutoUnattendSettings.xml"
        # Start
        copy-item $sourceXML1 $dest1
        copy-item $sourceXML2 $dest2
        Dismount-VHD -Path $VHD

    }
    }
#  Start VM if sufficient available memory
    if ((get-vm).MemoryStartup -gt (gwmi Win32_OperatingSystem).FreePhysicalMemory )
           {
              Start-VM $V.VMName
           }
        else
           {
                write-host "Insufficient available memory to start " $v.VMName
           }
  }