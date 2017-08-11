# Aerohive Corporate Account Sync
Aerohive Corporate Account Sync is a PowerShell Script using ACS APIs to automate the creation of User Accounts on HiveManager NG for domain users.

# Prerequisites
* This script has be tested on Windows 10 and Windows Server 2016 with PowerShell version 5.1.
* The computer has to have the PowerShell AD module installed. If it's not the case, you can use the ad_module.ps1 script to download and install it.
* The Windows PowerShell Script Execution Policy should allow to execute unsigned scripts. To change the locale Execution Policy configuration, and allow to use local unsigned script, you can use the command `Set-ExecutionPolicy RemoteSigned` 