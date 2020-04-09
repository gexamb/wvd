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
##Desktop Management and Administration                                  ##
##########################################################################

Write-Host "*****  STEP 1 OF 1 OF OS DEPLOYMENT  *****" -ForegroundColor Green

Write-Host "####################Starting Desktop Administration Configuration####################" -ForegroundColor Green

##Set Time Zone to PST
Set-TimeZone -Id "Pacific Standard Time"

##Disable User Account Control (UAC)
Write-Host "* Disabling User Account Control (UAC)" -ForegroundColor Green
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 0
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name "EnableLUA" -Value 0

##Enable Remote Management - WinRM
Write-Host "* Enabling Powershell Remote Management" -ForegroundColor Green
Enable-PSRemoting -Force

##Enable Remote Desktop
Write-Host "* Enabling Remote Desktop" -ForegroundColor Green
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name “fDenyTSConnections” -Value 0
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name “UserAuthentication” -Value 1
Enable-NetFirewallRule -DisplayGroup “Remote Desktop”

##Create new local IT administrator account
Write-Host "* Create new local admin account - IT-Admin" -ForegroundColor Green
New-LocalUser -Name "IT-Admin" -Description "IT Local Administrator" -AccountNeverExpires -NoPassword
Add-LocalGroupMember -Group "Administrators" -Member "IT-Admin"

##Adding domain admin groups
Write-Host "* Adding CSUN domain administrator groups to local Adminstrators group" -ForegroundColor Green
Add-LocalGroupMember -Group "Administrators" -Member S-1-5-21-789336058-1708537768-1957994488-186630 #Ent-Admins

##Update Windows Firewall Rules
Write-Host "* Configuring Windows Firewall" -ForegroundColor Green
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)"
#Disable-NetFirewallRule -DisplayName "Cortana"
Disable-NetFirewallRule -DisplayGroup "Cast to Device functionality"
Disable-NetFirewallRule -DisplayGroup "AllJoyn Router"
Disable-NetFirewallRule -DisplayGroup "DIAL protocol server"
Disable-NetFirewallRule -DisplayGroup "Work or school account"
Disable-NetFirewallRule -DisplayGroup "Your account"
New-NetFirewallRule -DisplayName "OEM" -Direction Inbound -LocalPort 1820 -Protocol TCP -Action Allow
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

##Clear all event logs
#Write-Host "* Clearing all existing Event Viewer logs" -ForegroundColor Green
#wevtutil el | Foreach-Object {wevtutil cl “$_”}

##Windows Update Settings
Write-Host "* Customizing Windows Update settings" -ForegroundColor Green
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Value 2
$ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
$ServiceManager.ClientApplicationID = "My App"
$ServiceManager.AddService2( "7971f918-a847-4430-9279-4a52d1efe18d",7,"")

##Disable and rename Guest account
Write-Host "* Disabling Guest account" -ForegroundColor Green
Get-LocalUser -Name "Guest" | Disable-LocalUser
Rename-LocalUser -Name "Guest" -NewName "!VOID!Guest"

##########################################################################
##Security Remediations                                                 ##
##########################################################################
Write-Host "####################Starting Security Remediations Configuration####################" -ForegroundColor Green

##Qualys Cloud Agent settings
New-Item -Path 'HKLM:\Software\Qualys\QualysAgent\ScanOnDemand\' -Name Vulnerability -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Qualys\QualysAgent\ScanOnDemand\Vulnerability\' -Name CpuLimit -Value 100 -Type DWord
Set-ItemProperty -Path 'HKLM:\Software\Qualys\QualysAgent\ScanOnDemand\Vulnerability\' -Name ScanOnDemand -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\Software\Qualys\QualysAgent\ScanOnDemand\Vulnerability\' -Name ScanOnStartup -Value 1 -Type DWord

##########################################################################
##Desktop and Explorer Customization                                    ##
##########################################################################
Write-Host "####################Starting Desktop and Explorer Customization####################" -ForegroundColor Green

<# HKCU registry changes do not work when script runs under SYSTEM account. Must run this as an admin
##Disable Storage Sense for VDI deployments (Windows 10 Enterprise or Multi-Session)
New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\' -Name StoragePolicy
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\" -Name 01 -Value 0 -Type DWord

##Show hidden files and folders in Explorer
Write-Host "* Show hidden files" -ForegroundColor Green
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
New-ItemProperty -Path $RegistryPath -Name "HideIcons" -Value "0" -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $RegistryPath -Name "HideFileExt" -Value "0" -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $RegistryPath -Name "Hidden" -Value "1" -PropertyType DWORD -Force | Out-Null

##Create default Desktop icons
Write-Host "* Creating default Desktop icons" -ForegroundColor Green
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "HideDesktopIcons" -Force | Out-Null
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons" -Name "NewStartPanel" -Force | Out-Null

$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
## -- My Computer
New-ItemProperty -Path $RegistryPath -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value "0" -PropertyType DWORD -Force | Out-Null
## -- Recycle Bin
New-ItemProperty -Path $RegistryPath -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value "0" -PropertyType DWORD -Force | Out-Null
#>