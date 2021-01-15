# Check in Admin mode

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

# set to stop if PowerShell cmdlet error occurs
$ErrorActionPreference = "Stop"

# Load functions
Set-Location 'P:\Scripts\Lab Setup'

# Load Generic functions for creating VMs etc
get-item 'P:\Functions\psvm*.ps1' | %{.$_}

# Run scripts for creating Lab environment
# & '.\Lab VMs - 1 - Create.ps1'
# & '.\Lab VMs - 2 - Configure.ps1'
& '.\Lab VMs - 3 - Customise for C6M1.ps1'