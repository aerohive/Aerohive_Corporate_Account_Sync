# Aerohive Corporate Account Sync
Aerohive Corporate Account Sync is a PowerShell Script using ACS APIs to automate the creation of User Accounts on HiveManager NG for domain users.
It can be used with HiveManager NG Cloud or HiveManager NG OnPremise (requires the Sept. 2017 release).


This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# Prerequisites
* This script has be tested on Windows 10 and Windows Server 2016 with PowerShell version 5.1.
* The computer has to have the PowerShell AD module installed. If it's not the case, you can use the ad_module.ps1 script to download and install it.
* The Windows PowerShell Script Execution Policy should allow to execute unsigned scripts. To change the locale Execution Policy configuration, and allow to use local unsigned script, you can use the command `Set-ExecutionPolicy RemoteSigned`

# Configuration 
Edit the settings_example.ini file to configure the script. 
You can also move the settings_example.ini file to settings.ini in the same folder as the script itself. Otherwise, you will have to specify the settings.ini location with the -f flag when running the script.

# Usage
    NAME
            Aerohive Corporate Account Sync

    SYNOPSIS
            acas.ps1 [OPTION [WORD]]

    DESCRIPTION
            Aerohive Corporate Account Sync is a PowerShell Script using ACS 
            APIs to automate the creation of User Accounts on HiveManager NG
            for domain users.
            THIS SCRIPT IS NOT MODIFYING ANY DOMAIN USERS! It is just using 
            domain users' information to create User Accounts on HiveManager NG.

        options are
                -h
                -help                   This help.

                -f <file>
                -file <file>            Path to the configuration file. By default, 
                                        the script will try to find the settings.ini 
                                        file in script location.

                -t 
                -test <ad_user>         Test the AD configuration and display the 
                                        available fields.

                -a
                -audit                  Audit the AD and ACS users to list differences.
                                        When the -a flag is present, the script will 
                                        not create/remove any account.

                -g
                -group                  List all the available User Groups from ACS. This
                                        can be used to configure the "acsUserGroupId"
                                        parameters from the settings file.

                -r
                -register               Register this script as a ScheduleJob. This will
                                        execute the script every day.
                                        This command required the administrator rights.

                -u
                -unregister             Unregister the ScheduleJob for this script.
                                        This command required the administrator rights.