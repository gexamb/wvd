##########################################################################
##########################################################################       
##Script for customizing new Windows 10 OS template                     ##
##                                                                      ##
##Author: George Babudzhyan 03/26/2020                                  ##
##Purpose: To use this script to prepare and customize a new Windows    ##
##desktop installation via PowerShell for use as a template VM          ##
##########################################################################
##########################################################################

##########################################################################
##Server Management and Administration                                  ##
##########################################################################

Write-Host "*****  STEP 1 OF 4 OF OS DEPLOYMENT  *****" -ForegroundColor Green

Write-Host "####################Starting Desktop Administration Configuration####################" -ForegroundColor Green

##Set Time Zone to PST
Set-TimeZone -Id "Pacific Standard Time"

##Disable User Account Control (UAC)
Write-Host "* Disabling User Account Control (UAC)" -ForegroundColor Green
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name "EnableLUA" -Value 0

##Disable Storage Sense for VDI deployments (Windows 10 Enterprise or Multi-Session)
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\" -Name 01 -Value 0 -Type DWord

##Enable Remote Management - WinRM
Write-Host "* Enabling Powershell Remote Management" -ForegroundColor Green
Enable-PSRemoting -Force

##Enable Remote Desktop
Write-Host "* Enabling Remote Desktop" -ForegroundColor Green
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name “fDenyTSConnections” -Value 0
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name “UserAuthentication” -Value 1
Enable-NetFirewallRule -DisplayGroup “Remote Desktop”

##Create new local IT administrator account
Set-LocalUser -Name "IT-Admin" -PasswordNeverExpires 1
<#
Write-Host "* Create new local admin account - IT-Admin" -ForegroundColor Green
New-LocalUser -Name "IT-Admin" -Description "IT Local Administrator" -AccountNeverExpires -NoPassword
Add-LocalGroupMember -Group "Administrators" -Member "IT-Admin"
#>

##Adding domain admin groups
Write-Host "* Adding CSUN domain administrator groups to local Adminstrators group" -ForegroundColor Green
Add-LocalGroupMember -Group "Administrators" -Member S-1-5-21-789336058-1708537768-1957994488-186630 #Ent-Admins

##Update Windows Firewall Rules
Write-Host "* Configuring Windows Firewall" -ForegroundColor Green
#Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)"
Disable-NetFirewallRule -DisplayName "Cortana"
Disable-NetFirewallRule -DisplayGroup "Cast to Device functionality"
Disable-NetFirewallRule -DisplayGroup "AllJoyn Router"
Disable-NetFirewallRule -DisplayGroup "DIAL protocol server"
Disable-NetFirewallRule -DisplayGroup "Work or school account"
Disable-NetFirewallRule -DisplayGroup "Your account"
#New-NetFirewallRule -DisplayName "OEM" -Direction Inbound -LocalPort 1820 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Qualys" -Direction Inbound -RemoteAddress 130.166.1.9 -Action Allow

##Clean-up Windows Update repository
<#
Write-Host "Cleaning up the default Windows update repository folder" -ForegroundColor Green
Stop-Service -Name wuauserv -Force
Remove-Item -Path C:\Windows\SoftwareDistribution\* -Recurse -Force
Start-Service -Name wuauserv
#>

##Create IT WinSys related scheduled tasks
Write-Host "* Creating new scheduled task for server reboot" -ForegroundColor Green
#Enable task history
wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true
#Create folder called IT in Task Scheduler
$scheduleObject = New-Object -ComObject schedule.service
$scheduleObject.connect()
$rootFolder = $scheduleObject.GetFolder("\")
$rootFolder.CreateFolder("IT")
##Create scheduled task to reboot server under IT\ folder
#Specify the trigger settings
$Trigger= New-ScheduledTaskTrigger -At "01/01/2019 10:00:00 PM" –Once
#Specify the account to run the script
$User= "NT AUTHORITY\SYSTEM"
#Specify what program to run and with its parameters
$Action= New-ScheduledTaskAction -Execute "shutdown" -Argument "-f -r -t 0"
#Specify the name of the task
Register-ScheduledTask -TaskName "IT\ScheduleReboot" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest –Force

##Disable unnecessary scheduled tasks
Write-Host "* Disabling unused scheduled tasks" -ForegroundColor Green
Get-ScheduledTask -TaskPath "\Microsoft\XblGameSave\" | Disable-ScheduledTask

##Disable unnecessary services
Write-Host "* Disabling unused system services" -ForegroundColor Green
#.\disable_services_2k16.ps1

##Increase size of standard Windows Event Logs
<#
Write-Host "* Increasing the log size for Event Viewer logs" -ForegroundColor Green
Limit-EventLog -LogName Application -MaximumSize 128MB -OverflowAction OverwriteAsNeeded
Limit-EventLog -LogName Security -MaximumSize 128MB -OverflowAction OverwriteAsNeeded
Limit-EventLog -LogName System -MaximumSize 128MB -OverflowAction OverwriteAsNeeded
#>

##Clear all event logs
Write-Host "* Clearing all existing Event Viewer logs" -ForegroundColor Green
wevtutil el | Foreach-Object {wevtutil cl “$_”}

##Network Settings
Write-Host "####################Starting Network Settings Configuration####################" -ForegroundColor Green

#Disable LMHOSTS
Write-Host "* Disabling LMHosts" -ForegroundColor Green
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\ -Name EnableLMHOSTS -Value 0

#Disable NetBIOS over TCP\IP
Write-Host "* Disabling NetBIOS" -ForegroundColor Green
$adapters=(gwmi win32_networkadapterconfiguration )
Foreach ($adapter in $adapters){
  $adapter.settcpipnetbios(2)
}

#Disable unneeded network protocols
Write-Host "* Disabling unused network protocols" -ForegroundColor Green
Get-NetAdapterBinding -DisplayName "QoS Packet Scheduler","Internet Protocol Version 6 (TCP/IPv6)","Link-Layer Topology Discovery Responder","Link-Layer Topology Discovery Mapper I/O Driver","Microsoft LLDP Protocol Driver" | Set-NetAdapterBinding -Enabled $false

#Set the first NIC (VMXNET3) to a low metric
<#
Write-Host "* Setting the first NIC to have a low metric" -ForegroundColor Green
Set-NetIPInterface -InterfaceAlias "Ethernet0" -InterfaceMetric 5
#>

##Windows Update Settings
Write-Host "* Customizing Windows Update settings" -ForegroundColor Green
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Value 2
$ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
$ServiceManager.ClientApplicationID = "My App"
$ServiceManager.AddService2( "7971f918-a847-4430-9279-4a52d1efe18d",7,"")

##Enable Telnet client
<#
Write-Host "* Enabling telnet client" -ForegroundColor Green
Install-WindowsFeature -name Telnet-Client
#>

##########################################################################
##Security Hardening                                                    ##
##########################################################################
Write-Host "####################Starting Security Hardening Configuration####################" -ForegroundColor Green

##Set Security Options - Local Computer Policy > Windows Settings > Security Settings > Local Policies
<#
Write-Host "* Setting Local Security Options" -ForegroundColor Green
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 4

secedit /configure /db C:\Windows\security\local.sdb /cfg .\secpol.cfg

## Set Audit Policy - Local Computer Policy > Windows Settings > Security Settings > Local Policies
Write-Host "* Setting Local Audit Policy" -ForegroundColor Green
auditpol /set /category:"Account Logon","Account Management","Logon/Logoff","Policy Change","Privilege Use","System" /failure:enable /success:enable     
auditpol /set /category:"DS Access","Object Access" /failure:enable /success:disable
auditpol /set /category:"Detailed Tracking" /failure:disable /success:disable

## Set User Rights Assignment - Local Computer Policy > Windows Settings > Security Settings > Local Policies
Write-Host "* Setting Local User Rights Assignment" -ForegroundColor Green
.\ntrights.exe +r SeNetworkLogonRight -u "Authenticated Users"
.\ntrights.exe +r SeNetworkLogonRight -u "ENTERPRISE DOMAIN CONTROLLERS"
.\ntrights.exe -r SeNetworkLogonRight -u "Everyone"
.\ntrights.exe -r SeNetworkLogonRight -u "Users"
.\ntrights.exe -r SeInteractiveLogonRight -u "Users"
.\ntrights.exe +r SeDenyNetworkLogonRight -u "Guests"
.\ntrights.exe +r SeDenyNetworkLogonRight -u "Guest"
.\ntrights.exe +r SeDenyNetworkLogonRight -u "!VOID!Guest"
.\ntrights.exe +r SeDenyNetworkLogonRight -u "Anonymous"
.\ntrights.exe +r SeDenyRemoteInteractiveLogonRight -u "Guests"
.\ntrights.exe +r SeDenyInteractiveLogonRight -u "Guests"
.\ntrights.exe +r SeDenyServiceLogonRight -u "Guests"
.\ntrights.exe +r SeDenyBatchLogonRight -u "Guests"
.\ntrights.exe -r SeBatchLogonRight -u "Backup Operators"
.\ntrights.exe -r SeBatchLogonRight -u "Performance Log Users"
#>

##Disable and rename Guest account
Write-Host "* Disabling Guest account" -ForegroundColor Green
Get-LocalUser -Name "Guest" | Disable-LocalUser
Rename-LocalUser -Name "Guest" -NewName "!VOID!Guest"

##########################################################################
##Security Remediations                                                 ##
##########################################################################
Write-Host "####################Starting Security Remediations Configuration####################" -ForegroundColor Green

##Set path for HKU Registry Hive
New-PSDrive HKU Registry HKEY_USERS

Write-Host "* Setting registry keys" -ForegroundColor Green

<#
##CredSSP RDP Exception
New-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\ -Name Parameters -Force | Out-Null
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters -Name AllowEncryptionOracle -Value 1 -Type DWord

##Disable Address Sharing
Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\AFD\Parameters -Name DisableAddressSharing -Value 1 -Type DWord

##Hardened Paths 
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Type String
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Type String

##Internet Explorer Feature Control Fix
New-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\' -Name FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING -Force | Out-Null
New-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\' -Name FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX -Force | Out-Null
New-Item -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\' -Name FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING -Force | Out-Null
New-Item -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\' -Name FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX -Force | Out-Null

Set-ItemProperty -Path 'HKLM:\Software\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING' -Name iexplore.exe -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\Software\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name iexplore.exe -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING' -Name iexplore.exe -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX' -Name iexplore.exe -Value 1 -Type DWord

##NoDriveTypeAutoRun
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -Value 255 -Type DWord
New-Item -Path HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\ -Name Explorer -Force | Out-Null
Set-ItemProperty -Path HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -Value 255 -Type DWord

##Spectre Meltdown - Memory Management
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride -Value 8 -Type DWord
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask -Value 3 -Type DWord

##Disable Windows SmartScreen
Write-Host "* Disabling Windows SmartScreen" -ForegroundColor Green
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -Value 0 -Type DWord

##Disable Internet Explorer Enhanced Security Configuration
Write-Host "* Disabling IE ESC for Administrators" -ForegroundColor Green
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -Type DWord

##SCHANNEL - Ciphers and Protocols - SSL\TLS
Write-Host "* Setting SSL\TLS registry keys" -ForegroundColor Green
Invoke-Command {reg import .\schannel.reg | Out-Null}
#>

##Qualys Cloud Agent settings
New-Item -Path 'HKLM:\Software\Qualys\QualysAgent\ScanOnDemand\' -Name Vulnerability -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Qualys\QualysAgent\ScanOnDemand\Vulnerability\' -Name CpuLimit -Value 100 -Type DWord
Set-ItemProperty -Path 'HKLM:\Software\Qualys\QualysAgent\ScanOnDemand\Vulnerability\' -Name ScanOnDemand -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\Software\Qualys\QualysAgent\ScanOnDemand\Vulnerability\' -Name ScanOnStartup -Value 1 -Type DWord

##########################################################################
##Desktop and Explorer Customization                                    ##
##########################################################################
Write-Host "####################Starting Desktop and Explorer Customization####################" -ForegroundColor Green

##Show hidden files and folders in Explorer
Write-Host "* Show hidden files" -ForegroundColor Green
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
New-ItemProperty -Path $RegistryPath -Name "HideIcons" -Value "0" -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $RegistryPath -Name "HideFileExt" -Value "0" -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $RegistryPath -Name "Hidden" -Value "1" -PropertyType DWORD -Force | Out-Null

##Unhide Notification Area icons
<#
Write-Host "* Unhiding notification area icons" -ForegroundColor Green
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value "0" -PropertyType DWORD -Force | Out-Null
#>

##Create default Desktop icons
Write-Host "* Creating default Desktop icons" -ForegroundColor Green
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "HideDesktopIcons" -Force | Out-Null
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name "NewStartPanel" -Force | Out-Null

$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
## -- My Computer
New-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value "0" -PropertyType DWORD -Force | Out-Null
## -- Control Panel
#New-ItemProperty -Path $RegistryPath -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value "0" -PropertyType DWORD -Force | Out-Null
## -- Recycle Bin
New-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value "0" -PropertyType DWORD -Force | Out-Null

##Add Windows tools shortcuts to Desktop
<#
Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Computer Management.lnk" -Destination "$env:USERPROFILE\Desktop"
Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Services.lnk" -Destination "$env:USERPROFILE\Desktop"
Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Windows Firewall with Advanced Security.lnk" -Destination "$env:USERPROFILE\Desktop"
#>

##Customize Start Menu - copy to default profile
<#
Write-Host "* Customizing Start Menu" -ForegroundColor Green
Copy-Item ".\LayoutModification.xml" -Destination "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell"
Copy-Item ".\LayoutModification.xml" -Destination "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Shell"
#>

##Copy and enable BGInfo background splash
<#
Write-Host "* Enabling background info splash screen" -ForegroundColor Green
Copy-Item "C:\_IT\BGInfo\normal.bat" -Destination "C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
Copy-Item "C:\_IT\BGInfo\normal.bat" -Destination "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
#>

##Set RunOnce to start next script at startup for cloning profile
<#
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name "2-clone_profile" -Value "C:\osdeploy\2-clone_profile.bat" -Type String
#>

##########################################################################
##Desktop Optimization Running - OSOT                                   ##
##########################################################################

#.\VMwareOSOptimizationTool.exe -o -t .\CSUN_WinSys_Win10.xml -notification disable -v > .\osotlog.txt 2>&1

#Read-Host -Prompt "Computer will be rebooted. Login as 'IT-Admin' and change password. Press Enter to exit"

##Restart the computer
#Restart-Computer -Force