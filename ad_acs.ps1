
param(
    [Parameter(Mandatory=$false)] 
    [alias ('file', 'f')]
    [string]$configFile = $PSScriptRoot + "\settings.ini",

    [Parameter(Mandatory=$false)] 
    [alias ('test', 't')]
    [string]$testUser,

    [Parameter(Mandatory=$false)] 
    [alias ('audit', 'a')]
    [switch]$doNotCreate,

    [Parameter(Mandatory=$false)] 
    [alias ('register', 'r')]
    [switch]$registerJob,
    [Parameter(Mandatory=$false)] 
    [alias ('unregister', 'u')]
    [switch]$unregisterJob,

    [Parameter(Mandatory=$false)] 
    [alias ('help', 'h')]
    [switch]$showHelp
)
$scriptLocation=$PSScriptRoot
$scriptName="ad_acs.ps1"

<#--------------------------------------------------------------
LOAD SETTINGS
--------------------------------------------------------------#>
function LoadSettings(){
    Write-Host "Loading parameters from $configFile"
    $params = @{}
    Get-Content $configFile | foreach-object -process {
        $k = [regex]::split($_, '=')
        if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True) -and ($k[0].StartsWith('#') -ne $True)) { 
            $params.Add($k[0], $k[1].Trim().Trim('"').Trim("'")) 
        } 
    }
    $script:clientId = $params.clientId
    $script:clientSecret = $params.clientSecret
    $script:redirectUrl = $params.redirectUrl
    $script:vpcUrl = $params.vpcUrl
    $script:accessToken = $params.accessToken
    $script:refreshToken = $params.refreshToken
    $script:expireDate = $params.expireDate
    $script:ownerId = $params.ownerId
    $script:acsUserGroupId = $params.acsUserGroupId
    $script:acsUserName = $params.acsUserName.ToString()
    $script:acsEmail = $params.acsEmail
    $script:acsPhone = $params.acsPhone
    $script:acsOrganization = $params.acsOrganization
    if ($params.acsDeliveryMethod -like "NO_DELIVERY" -or 
        $params.acsDeliveryMethod -like "EMAIL" -or
        $params.acsDeliveryMethod -like "SMS" -or
        $params.acsDeliveryMethod -like "EMAIL_AND_SMS") 
    {
        $script:acsDeliveryMethod = $params.acsDeliveryMethod
    } else {
        Write-Error "Wrong 'acsDeliveryMethod' parameter. Please correct it and start again. Exiting..."
        exit 254
    }
    $script:adGroup = $params.adGroup
    $script:logFile = $params.logFile
    try {$script:logToAFile = [System.Convert]::ToBoolean($params.logToAFile)}
    catch {
        Write-Error "Wrong 'logToAFile' parameter. Please correct it and start again. Exiting..."
        exit 254
    }
    try {$script:logToConsole = [System.Convert]::ToBoolean($params.logToConsole)}
    catch {
        Write-Error "Wrong 'logToConsole' parameter. Please correct it and start again. Exiting..."
        exit 254
    }
    if ($params.logLevel -like "debug" -or $params.logLevel -like "info" -or $params.logLevel -like "error") {$script:logLevel = $params.logLevel}
    else {
        Write-Error "Wrong 'logLevel' parameter. Please correct it and start again. Exiting..."
        exit 254
    }

    $script:headers = @{
        "X-AH-API-CLIENT-SECRET"       = "$clientSecret";
        "X-AH-API-CLIENT-ID"           = "$clientId";
        "X-AH-API-CLIENT-REDIRECT-URI" = "$redirectUrl";
        "Authorization"                = "Bearer $accessToken"
    }
}
<#--------------------------------------------------------------
SCRIPT
--------------------------------------------------------------#>

###############################################################
######### LOGGING
###############################################################
function LogError($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$date $time ERROR: $mess"
    if ($logToAFile) {Add-content $logFile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Red}
}
function LogInfo ($mess) {
    if ($logLevel -like "debug" -or $logLevel -like "info") {
        $date = Get-Date -Format d
        $time = Get-Date -Format HH:mm:ss.fff
        $logstring = "$date $time INFO: $mess"
        if ($logToAFile) {Add-content $logFile -value $logstring}
        if ($logToConsole) {Write-Host $logstring -ForegroundColor Green}
    }
}
function LogDebug($mess) {
    if ($logLevel -like "debug") {
        $date = Get-Date -Format d
        $time = Get-Date -Format HH:mm:ss.fff
        $logstring = "$date $time DEBUG: $mess"
        if ($logToAFile) {Add-content $logFile -value $logstring}
        if ($logToConsole) {Write-Host $logstring -ForegroundColor Gray}
    }
}

######################################################
######### ACS Requests Functions
######################################################

function AcsError($data) {
    LogError("Got HTTP" + $data.error.status + ": " + $data.error.code)
    LogError("Message: " + $data.error.message)
}
function GetUsersFromAcs() {
    try { 
        $response = (Invoke-RestMethod -Uri "https://$vpcUrl/xapi/v1/identity/credentials?ownerId=$ownerId&userGroup=$acsUserGroupId" -Headers $headers -Method Get)
    }
    catch {   
        LogError("Can't retrieve Users from ACS")
        AcsError(ConvertFrom-Json $_.ErrorDetails.Message)
        LogError("Exiting...")
        exit 255
    } 
    return $response.data
}

function CreateAcsAccount($adUser) {
    if ($doNotCreate){
        LogInfo("CHECK ONLY! The account " + $adUser.$acsUserName + " should be deleted" )
    } else {
        LogInfo("Creating " + $adUser.$acsUserName)
        $acsUser = @{
            "userName"      = $adUser.$acsUserName;
            "email"         = $adUser.$acsEmail;
            "organization"  = $adUser.$acsOrganization;
            "phone"         = $adUser.$acsPhone;
            "firstName"     = $acsUser.Name;
            "groupId"       = $acsUserGroupId;
            "deliverMethod" = $acsDeliveryMethod;
            "policy"        = "PERSONAL";
            "purpose"       = "AD User"
        }
        $json = $acsUser | ConvertTo-Json
        try {
            $response = Invoke-RestMethod -Uri "https://$vpcUrl/xapi/v1/identity/credentials?ownerId=$ownerId" -Method Post -Headers $headers -Body $json -ContentType "application/json"
        }
        catch {
            LogError("Can't create new User " + $adUser.$acsUserName)
            AcsError(ConvertFrom-Json $_.ErrorDetails.Message)
        }
    }
    return $response
}

function DeleteAcsAccount($acsUser) {
    if ($doNotCreate){
        LogInfo("CHECK ONLY! The account " + $acsUser.userName + " with Id " + $acsUser.id + " should be deleted" )
    } else {
        LogInfo("Deleting " + $acsUser.userName + " with Id " + $acsUser.id)
        $acsUserId = $acsUser.id
        try {
            $response = Invoke-RestMethod -Uri "https://$vpcUrl/xapi/v1/identity/credentials?ownerId=$ownerId&ids=$acsUserId" -Method Delete -Headers $headers
        }
        catch {
            LogError("Can't delete the User " + $acsUser.userName)
            AcsError(ConvertFrom-Json $_.ErrorDetails.Message)
        }
        return $response
    }
}

######################################################
######### AD Requests Functions
######################################################
function GetUsersFromAd() {
    $adAccounts = @()
    $users = Get-ADGroupMember $adGroup -Recursive 
    foreach ($user in $users) {
        $temp = Get-ADUser $user.SamAccountName -Properties $acsUserName, $acsEmail, $acsOrganization, $acsPhone
        if ($temp) { 
            $adAccounts += $temp    
        }
    }
    return $adAccounts
}

function TestUser() {
    $users = Get-ADGroupMember $adGroup -Recursive 
    foreach ($user in $users){
        if ($user.SamAccountName -like "$testUser") {
                Get-ADUser $user.SamAccountName -Properties $acsUserName, $acsEmail, $acsOrganization, $acsPhone
            }
    }
}

######################################################
######### start process
######################################################
function StartProcess(){
    $acsUsers = GetUsersFromAcs
    $adUsers = GetUsersFromAd
    $validAcsUsers = @()
    $i = 0
    foreach ($adUser in $adUsers) {
        $acsAccountExists = $false
        foreach ($acsUser in $acsUsers) {
            if ($adUser.$acsUserName -like $acsUser.userName -And $adUser.Enabled -like "False") {
                $mess = $adUser.$acsUserName + " is disabled. Should be removed"
                LogDebug($mess)
                DeleteAcsAccount($acsUser)
                break     
            }
            elseif ($adUser.$acsUserName -like $acsUser.userName -And $adUser.Enabled -like "True") {
                $acsAccountExists = $true
                $validAcsUsers += $acsUser
                break
            } 
        }
        if (-not $acsAccountExists) {
            $mess = $adUser.$acsUserName + " doesn't have any PPSK. Should be created"
            LogDebug($mess)
            CreateAcsAccount($adUser)
        }
        else {
            $mess = $adUser.$acsUserName + " is enabled and already has a PPSK. nothing to do"
            LogDebug($mess)
        }
        $i++
        $percentage = (($i / $adUsers.length) * 100)
        Write-Progress -activity "Checking AD Users" -status "Progress: " -PercentComplete $percentage  -CurrentOperation "$percentage%"
    }


    $i = 0
    foreach ($acsUser in $acsUsers) {
        if ( $validAcsUsers -notcontains $acsUser) {
            $mess = $acsUSer.userName + " should be removed because it does not belong to the AD"
            LogDebug($mess)
            DeleteAcsAccount($acsUser)
        }
        $i++
        $percentage = (($i / $acsUsers.length) * 100)
        Write-Progress -activity "Checking Aerohive Users" -status "Progress: " -PercentComplete $percentage  -CurrentOperation "$percentage%"
    }
}

######################################################
######### usage
######################################################
function Usage(){
    $usage=@"
NAME
        Aerohive Corporate Account Sync

SYNOPSIS
        $scriptName [OPTION [WORD]]

DESCRIPTION
        Aerohive Corporate Account Sync is a PowerShell Script using ACS 
        APIs to automate the creation of User Accounts on HiveManager NG
        for domain users.
        THIS SCRIPT IS NOT MODIFYING THE AD USERS! It is just using domain
        users' information to create User Accounts on HiveManager NG.

    options are
            -h
            -help               This help.

            -f <file>
            -file <file>        Path to the configuration file. By default, 
                                the script will try to find the settings.ini 
                                file in script location.

            -t 
            -test <ad_user>     Test the AD configuration and display the 
                                available fields.

            -a
            -audit              Audit the AD and ACS users to list differences.
                                When the -a flag is present, the script will 
                                not create/remove any account.
            
            -r
            -register           Register this script as a ScheduleJob. This will
                                execute the script every day.
                                This command required the administrator rights.

            -u
            -unregister         Unregister the ScheduleJob for this script.
                                This command required the administrator rights.
"@
    Write-Host $usage
}

######################################################
######### Register/Unregister the script
######################################################
function Register() {
    $id = (Get-ScheduledJob -Name ACAS -ErrorAction SilentlyContinue).Id
    if ($id -eq $null){
        Write-Warning "Do not move the script location once registered."
        Write-Warning "Currently, the registration process only works from a PowerShell with the adminsitrator rights."
        $response="x"
        while ($response -notlike "y" -and $response -notlike "n" ){
            $response = Read-Host "Do you want to register this script to run it every day (y/n)?"
        }
        if ($response -like "y"){
            $trigger=New-JobTrigger -Daily -at "2:00AM"
            Register-ScheduledJob -Name "ACAS" -FilePath "$scriptLocation\$scriptName" -Trigger $trigger
        } else {Write-Host "Nothing done."}
    } else {
        Write-Host "This script is already registered."
        Write-Host "Please unregister is first with the '$scriptName -u' command"
    }
}
function Unregister(){
    $id = (Get-ScheduledJob -Name ACAS -ErrorAction SilentlyContinue).Id
    if ($id -ne $null){
        $response="x"
        while ($response -notlike "y" -and $response -notlike "n" ){
            $response = Read-Host "Do you want to unregister this script (y/n)?"
        }
        if ($response -like "y"){
            Unregister-ScheduledJob -id $id
            Write-Host "ScheduleJob unregistered."
            Write-Host Get-ScheduledJob
        } else {Write-Host "Nothing done."}
    } else {
        Write-Host "Not able to find the scheduledJob ACAS."
    }
}
######################################################
######### entry point
######################################################

if ($showHelp) {Usage}
elseif ($testUser) {TestUser}
elseif ($registerJob) {Register}
elseif ($unregisterJob) {Unregister}
else {
    LoadSettings
    LogInfo("Starting process")
    StartProcess
    LogInfo("Process finisehd")
}