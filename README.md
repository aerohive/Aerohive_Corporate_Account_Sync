# Aerohive Corporate Account Sync
Aerohive Corporate Account Sync is a PowerShell Script using ACS APIs to automate the creation of User Accounts on HiveManager NG for domain users.

# Prerequisites
* This script has be tested on Windows 10 and Windows Server 2016 with PowerShell version 5.1.
* The computer has to have the PowerShell AD module installed. If it's not the case, you can use the ad_module.ps1 script to download and install it.
* The Windows PowerShell Script Execution Policy should allow to execute unsigned scripts. To change the locale Execution Policy configuration, and allow to use local unsigned script, you can use the command `Set-ExecutionPolicy RemoteSigned`

# Usage
## SYNOPSIS
        acas.ps1 [OPTION [WORD]]

## DESCRIPTION
        Aerohive Corporate Account Sync is a PowerShell Script using ACS 
        APIs to automate the creation of User Accounts on HiveManager NG
        for domain users.

## options are
* -h or -help:
This help.
* -f <file> or -file <file>:
Path to the configuration file. By default, the script will try to find the settings.ini file in script location.
* -t or -test <ad_user>:
Test the AD configuration and display the available fields.
* -c or -checkOnly:
Only check the accounts. When the -c flag is present, the script will not create/remove the the account form HiveMaager NG.

 