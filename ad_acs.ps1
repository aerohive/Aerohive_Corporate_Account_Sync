
param(
    [Parameter(Mandatory=$false, HelpMessage="Path to the configuration file.")] 
    [alias ('file', 'f')]
    [string]$configFile = $PSScriptRoot + "\settings.ini",

    [Parameter(Mandatory=$false, HelpMessage="Username to test with the current configuration.")] 
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
    [alias ('group', 'g')]
    [switch]$retrieveGroupId,

    [Parameter(Mandatory=$false)] 
    [alias ('help', 'h')]
    [switch]$showHelp
)
$scriptLocation=$PSScriptRoot
$scriptName="ad_acs.ps1"

<#--------------------------------------------------------------
LOAD SETTINGS
--------------------------------------------------------------#>
function checkEmpty($name, $value){
    if ($value -like ""){
        Write-Warning  "'$($name)' parameter can't be null. Please correct it and start again. Exiting..." 
        exit 255
    } else {return $value} 
}
function LoadSettings(){
    Write-Host "Loading parameters from $($configFile)"
    $params = @{}
    Get-Content $configFile | foreach-object -process {
        $k = [regex]::split($_, '=')
        if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True) -and ($k[0].StartsWith('#') -ne $True)) { 
            $params.Add($k[0], $k[1].Trim().Trim('"').Trim("'")) 
        } 
    }

    $script:clientId = checkEmpty "clientId" $params.clientId
    $script:clientSecret = checkEmpty "clientSecret" $params.clientSecret
    $script:redirectUrl = checkEmpty "redirectUrl" $params.redirectUrl
    $script:vpcUrl = checkEmpty "vpcUrl" $params.vpcUrl
    if ($params.vpcUrl -like "*.aerohive.com") {
        $script:cloud = $true
    } else { 
        $script:cloud = $false
        try {$validateSslCertificate = [System.Convert]::ToBoolean($params.validateSslCertificate)}
        catch {
            Write-Error "Wrong 'validateSslCertificate' parameter. Please correct it and start again. Exiting..."
            exit 254
        }
        if ($validateSslCertificate -like $false) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        }
    }
    $script:accessToken = checkEmpty "accessToken" $params.accessToken
    $script:refreshToken = checkEmpty "refreshToken" $params.refreshToken
    $script:expireDate = checkEmpty "expireDate" $params.expireDate
    $script:ownerId = checkEmpty "ownerId" $params.ownerId
    $script:acsUserGroupId = checkEmpty "acsUserGroupId" $params.acsUserGroupId
    $script:acsUserName = checkEmpty "acsUserName" $params.acsUserName.ToString()
    $script:acsEmail = checkEmpty "acsEmail" $params.acsEmail
    $script:acsPhone = checkEmpty "acsPhone" $params.acsPhone
    $script:acsOrganization = checkEmpty "acsOrganization" $params.acsOrganization
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
    $script:adGroup = checkEmpty "adGroup" $params.adGroup
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
    try {$script:sendEmailUpdate = [System.Convert]::ToBoolean($params.sendEmailUpdate)}
    catch {
        Write-Error "Wrong 'sendEmailUpdate' parameter. Please correct it and start again. Exiting..."
        exit 254
    }
    if ($sendEmailUpdate) {
        $script:smtpServer=checkEmpty "smtpServer" $params.smtpServer
        $script:smtpUserName=checkEmpty "smtpUserName" $params.smtpUserName
        $secpasswd = ConvertTo-SecureString $params.smtpPassword -AsPlainText -Force
        $script:smtpCreds = New-Object System.Management.Automation.PSCredential ($params.smtpUserName, $secpasswd)
        $script:smtpTo=checkEmpty "smtpTo" $params.smtpTo
        $script:smtpFrom=checkEmpty "smtpFrom" $params.smtpFrom
        $script:smtpSubject=checkEmpty "smtpSubject" $params.smtpSubject
    }

    $script:headers = @{
        "X-AH-API-CLIENT-SECRET"       = "$($clientSecret)";
        "X-AH-API-CLIENT-ID"           = "$($clientId)";
        "X-AH-API-CLIENT-REDIRECT-URI" = "$($redirectUrl)";
        "Authorization"                = "Bearer $($accessToken)"
    }
    $script:params = $params
}
<#--------------------------------------------------------------
SCRIPT
--------------------------------------------------------------#>
###############################################################
######### SCRIPT VARIABLES
###############################################################
$adAccountsNumber=0
$acsAccountsNumber=0
$createdAccounts=@()
$deletedAccounts=@()
$smtpBody=@()
###############################################################
######### LOGGING
###############################################################
function LogError($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$($date) $($time) ERROR: $($mess)"
    if ($logToAFile) {Add-content $logFile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Red}
    if ($sendEmailUpdate) {$script:smtpBody += $logstring}
}
function LogWarning($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$($date) $($time) WARNING: $($mess)"
    if ($logToAFile) {Add-content $logFile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Magenta}
    if ($sendEmailUpdate) {$script:smtpBody += $logstring}
}
function LogInfo ($mess) {
    if ($logLevel -like "debug" -or $logLevel -like "info") {
        $date = Get-Date -Format d
        $time = Get-Date -Format HH:mm:ss.fff
        $logstring = "$($date) $($time) INFO: $($mess)"
        if ($logToAFile) {Add-content $logFile -value $logstring}
        if ($logToConsole) {Write-Host $logstring -ForegroundColor Green}
        if ($sendEmailUpdate) {$script:smtpBody += $logstring}
    }
}
function LogDebug($mess) {
    if ($logLevel -like "debug") {
        $date = Get-Date -Format d
        $time = Get-Date -Format HH:mm:ss.fff
        $logstring = "$($date) $($time) DEBUG: $($mess)"
        if ($logToAFile) {Add-content $logFile -value $logstring}
        if ($logToConsole) {Write-Host $logstring -ForegroundColor Gray}
        if ($sendEmailUpdate) {$script:smtpBody += $logstring}
    }
}
function sendEmailUpdate(){
    if ($sendEmailUpdate) {
        $c = $createdAccounts | Out-String
        $d = $deletedAccounts | Out-String
        $l = $smtpBody | Out-String
        $body=@(
            "Number of user accounts (before changes):",
            "Windows Domain: $($adAccountsNumber)", 
            "Aerohive: $($acsAccountsNumber)",
            "",
            "Created accounts:",
            $c ,
            "",
            "Deleted accounts:",
            $d,
            "",
            "Logs:",
            $l
            )
        $body = $body | Out-String
        Send-MailMessage -To $smtpTo -From $smtpFrom -Subject $smtpSubject -SMTPServer $smtpServer -Credential $smtpCreds -Body $body
    }
}
######################################################
######### ACS Requests Functions
######################################################
function RetrieveGroupId(){
    try {
        LogInfo("Retrieving Aerohive Group Id.")
        $uri = "https://$($script:vpcUrl)/xapi/v1/identity/userGroups?ownerId=$($script:ownerId)"
        $response = Invoke-RestMethod -Uri $uri -Headers $script:headers -Method Get
    } catch {
        LogError("Can't retrieve User Groups from ACS")
        try {
            AcsError(ConvertFrom-Json $_.ErrorDetails.Message)            
        } catch {
            LogError("no message")
            Write-Host $_
        }
        LogError("Exiting...")
        exit 255
    } 
    
    if ($response.data.userGroups){
        $t =  $response.data.userGroups
       $t | Format-Table -AutoSize
    } else {
        Write-Host "There is no User Groups here..."
    }
}

function RefreshAccessToken(){
    
    try {
        LogWarning("ACS Access Token will expire in one week. Refreshing it.")
        if ($cloud) {
            $uri = "https://cloud.aerohive.com/services/oauth2/token"
        } else {
            $uri = "https://$($vpcUrl)/acct-webapp/services/oauth2/token"
        }
        $body = @{
            "client_secret"=$clientSecret;
            "client_id"=$clientId;
            "grant_type"="refresh_token";
            "refresh_token"=$refreshToken
        }
        $response = (Invoke-RestMethod -Uri $uri -Headers @{"Content-Type" = "application/x-www-form-urlencoded"} -Body $body -Method Post)
        LogInfo("ACS Access Token refreshed. Saving it.")
    } catch {
        LogError("Can't refresh ACS Access Token")
        LogError("Got HTTP$($_.Exception.Response.StatusCode.Value__): $($_.Exception.Response.StatusCode)")
        try {
            $mess = ConvertFrom-Json $_.ErrorDetails.Message
            LogError("Message: $($mess)")
        } catch {
            LogError("no message")
            Write-Host $_
        }
        LogError("Exiting...")
        exit 255
    }
    $expiresIn = $response.expires_in
    $epoch = [int64](([datetime]::UtcNow)-(get-date "1/1/1970")).TotalSeconds
    $expireDate = $epoch + $expiresIn
    if ($response.access_token -notlike $null -and $response.refresh_token -notlike $null){
        $settings = @"
################################################################################
# application credentials
# These information can be retreved from your Aerohive Developer Account
# at https://developer.aerohive.com
################################################################################
clientId=$($params.clientId)
clientSecret=$($params.clientSecret)
redirectUrl=$($params.redirectUrl)

################################################################################
# ACS account parameters 
# These information can be retrieved from your HMNG account in the 'Global 
# Settings' section and in the 'About' section
################################################################################
#if you are using HMNG OnPremise, use your HMNG FQDN
vpcUrl=$($params.vpcUrl)
accessToken=$($response.access_token)
refreshToken=$($response.refresh_token)
expireDate=$($expireDate)
ownerId=$($params.ownerId)
#This parameter is only used with HMNG OnPremise
#Set to "false" it you are using a self signed certificate 
#or is the station used to execute the script can't valide the SSL certificate
validateSslCertificate=$($params.validateSslCertificate)

################################################################################
# Group settings
################################################################################
# AD Group:
# The script will create a Wi-Fi account for every 
# user belonging to this Group 
adGroup=$($params.adGroup)
# Aerohive User Group Id
acsUserGroupId=$($params.acsUserGroupId)

################################################################################
# Credentials delivery
################################################################################
# may be 'NO_DELIVERY', 'EMAIL', 'SMS' or 'EMAIL_AND_SMS'
acsDeliveryMethod=$($params.acsDeliveryMethod)

################################################################################
# Logging parameters
################################################################################
# logToAFile may be true or false
logToAFile=$($params.logToAFile)
logFile=$($params.logFile)
# logToConsole may be true or false
logToConsole=$($params.logToConsole)
# logLevel can be debug, info, error
logLevel=$($params.logLevel)
################################################################################
# SMTP parameters
################################################################################
sendEmailUpdate=$($params.sendEmailUpdate)
smtpServer=$($params.smtpServer)
smtpUserName=$($params.smtpUserName)
smtpPassword=$($params.smtpPassword)
smtpTo=$($params.smtpTo)
smtpFrom=$($params.smtpFrom)
smtpSubject=$($params.smtpSubject)
################################################################################
# AD/Aerohive fields binding
# Edit these parameters only if you know what you are doing!!!
################################################################################
# bindings between ACS and AD parameters
acsUserName=$($params.acsUserName)
acsEmail=$($params.acsEmail)
# AD phone property can be MobilePhone, OfficePhone or HomePhone
# Be sure to use international phone number if you want to send the 
# credentials by SMS
acsPhone=$($params.acsPhone)
acsOrganization=$($params.acsOrganization)
"@
        $settings | Out-File $configFile
        LogInfo("New ACS Access Token saved successfully.")
        LogInfo("Reloading settings.")
        LoadSettings
    } else {
        Write-Warning "Refresh token failed. Exiting."
        exit 254
    }
}

function AcsError($data) {
    LogError("Got HTTP$($data.error.status): $($data.error.code)")
    LogError("Message: $($data.error.message)")
}
function GetUsersFromAcsPagination($page, $pageSize){
    Write-Host "turn $($page)"
    try { 
        $uri = "https://$($vpcUrl)/xapi/v1/identity/credentials?ownerId=$($ownerId)&userGroup=$($acsUserGroupId)&page=$($page)&pageSize=$($pageSize)"
        $response = (Invoke-RestMethod -Uri $uri -Headers $script:headers -Method Get)
    }
    catch {   
        LogError("Can't retrieve Users from ACS")
        try {
            AcsError(ConvertFrom-Json $_.ErrorDetails.Message)            
        } catch {
            LogError("no message")
            Write-Host $_
        }
        LogError("Exiting...")
        exit 255
    } 
    return $response
}
function GetUsersFromAcs() {
    LogDebug("Retrieving users from ACS.")
    $page=0
    $pageSize=1000
    $script:acsAccountsNumber = 0
    $totalCount = 999
    $tempAcsAccounts = @()
    while ($script:acsAccountsNumber -lt $totalCount) {
        $response = GetUsersFromAcsPagination $page $pageSize
        $totalCount = $response.pagination.totalCount
        $script:acsAccountsNumber += $response.pagination.countInPage
        if ($response.date -notlike $null){
            $tempAcsAccounts += $response.data
            $page ++
        } else { exit 10 }
    }
    LogDebug("$($script:acsAccountsNumber) user(s) retrieved.")
    return $tempAcsAccounts
}
function CreateAcsAccount($adUser) {
    if ($doNotCreate){
        LogInfo("CHECK ONLY! The account $($adUser.$acsUserName) should be deleted" )
    } else {
        LogInfo("Creating $($adUser.$acsUserName)")
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
            $uri = "https://$($vpcUrl)/xapi/v1/identity/credentials?ownerId=$($ownerId)"
            $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $json -ContentType "application/json"
            $script:createdAccounts += $adUser.$acsUserName
        }
        catch {
            LogError("Can't create new User $($adUser.$acsUserName)")
            try {
                AcsError(ConvertFrom-Json $_.ErrorDetails.Message)            
            } catch {
                LogError("no message")
                Write-Host $_
            }
        }
    }
    return $response
}

function DeleteAcsAccount($acsUser) {
    if ($doNotCreate){
        LogInfo("CHECK ONLY! The account $($acsUser.userName) with Id $($acsUser.id) should be deleted" )
    } else {
        LogInfo("Deleting $($acsUser.userName) with Id $($acsUser.id)")
        $acsUserId = $acsUser.id
        try {
            $uri = "https://$($vpcUrl)/xapi/v1/identity/credentials?ownerId=$($ownerId)&ids=$($acsUserId)"
            $response = Invoke-RestMethod -Uri $uri -Method Delete -Headers $headers
            $script:deletedAccounts += $acsUser.userName
        }
        catch {
            LogError("Can't delete the User $($acsUser.userName)")
            try {
                AcsError(ConvertFrom-Json $_.ErrorDetails.Message)            
            } catch {
                LogError("no message")
                $t = ConvertTo-Json $_
                Write-Host $t
            }        
        }
        return $response
    }
}

######################################################
######### AD Requests Functions
######################################################
function GetAdGroup(){
    try {
        $adGroupRetrieved = Get-ADGroup -filter {name -like $adGroup} 
    } catch {
        LogError "Can't retrieve the AD Group $($adGroup)"
        exit 253
    }
    return $adGroupRetrieved
}
function GetAdGroupMembers($adGroup){
    try {
        $users = Get-ADGroupMember -Recursive -Identity $adGroupRetrieved 
        $script:adAccountsNumber = $users.Count       
    } catch {
        LogError "Can't retrieve users from the AD Group $($adGroup)"
        exit 252
    }
    return $users
}
function GetUsersFromAd() {
    $adAccounts = @()
    $adGroupRetrieved = GetAdGroup
    $users = GetAdGroupMembers($adGroupRetrieved)
    foreach ($user in $users) {
        $temp = Get-ADUser -Identity $user.SamAccountName -Properties $acsUserName, $acsEmail, $acsOrganization, $acsPhone
        if ($temp) { 
            $adAccounts += $temp    
        }
    }
    return $adAccounts
}

function TestUser() {
    $adGroupRetrieved = GetAdGroup
    $users =GetAdGroupMembers($adGroupRetrieved)
    $userFound = $false
    foreach ($user in $users){
        if ($user.SamAccountName -like "$testUser") {
                $userFound = $true
                Get-ADUser -Identity $user.SamAccountName -Properties $acsUserName, $acsEmail, $acsOrganization, $acsPhone 
            }
    }
    if (-not $userFound){
        Write-Host "the user $($testUser) is not found."
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
                $mess = "$($adUser.$acsUserName) is disabled. Should be removed"
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
            $mess = "$($adUser.$acsUserName) doesn't have any PPSK. Should be created"
            LogDebug($mess)
            CreateAcsAccount($adUser)
        }
        else {
            $mess = "$($adUser.$acsUserName) is enabled and already has a PPSK. nothing to do"
            LogDebug($mess)
        }
        $i++
        $percentage = (($i / $adUsers.length) * 100)
        Write-Progress -activity "Checking AD Users" -status "Progress: " -PercentComplete $percentage  -CurrentOperation "$percentage%"
    }


    $i = 0
    foreach ($acsUser in $acsUsers) {
        if ( $validAcsUsers -notcontains $acsUser) {
            $mess = "$($acsUSer.userName) should be removed because it does not belong to the AD"
            LogDebug($mess)
            DeleteAcsAccount($acsUser)
        }
        $i++
        $percentage = (($i / $acsUsers.length) * 100)
        Write-Progress -activity "Checking Aerohive Users" -status "Progress: " -PercentComplete $percentage  -CurrentOperation "$percentage%"
    }
}

######################################################
######### Register/Unregister the script
######################################################
function Register() {
    $id = (Get-ScheduledJob -Name ACAS -ErrorAction SilentlyContinue).Id
    if ($id -eq $null){
        Write-Warning @"

Do not move the script location once registered.
"@
        Write-Warning @"

Currently, the registration process only works from a PowerShell with the adminsitrator rights.
"@
        Write-Host ""
        $response="x"
        while ($response -notlike "y"){
            $response = Read-Host "Do you want to use the settings.ini file $($configFile) (y/n)?"
            if ($response -like 'n'){
                $fileExists = $false
                while (-not $fileExists){
                    $configFile = Read-Host "setting.ini location"
                    if (Test-Path $configFile) {
                        $fileExists=$true
                        Write-Host "File found."
                    } else {
                        Write-Host "Can't find the file $($configFile)"
                    }
                }

            }
        }
        $response="x"
        while ($response -notlike "y" -and $response -notlike "n" ){
            $response = Read-Host "Do you want to register this script to run it every day (y/n)?"
        }
        if ($response -like "y"){
            $trigger=New-JobTrigger -Daily -at "2:00AM"
            $script = Join-Path $scriptLocation $scriptName
            $creds = Get-Credential
            Register-ScheduledJob -Name "ACAS" -FilePath $script -Trigger $trigger -Credential $creds -ArgumentList $configFile
        } else {Write-Host "Nothing done."}
    } else {
        Write-Host "This script is already registered."
        Write-Host "Please unregister is first with the '$($scriptName) -u' command"
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
            
            -g
            -group              List all the available User Groups from ACS. This
                                can be used to configure the "acsUserGroupId"
                                parameters from the settings file.

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
######### entry point
######################################################

if ($showHelp) {Usage}
elseif ($testUser) {
    LoadSettings
    TestUser
}
elseif ($registerJob) {Register}
elseif ($unregisterJob) {Unregister}
elseif ($retrieveGroupId) {
    LoadSettings
    RetrieveGroupId
}
else {
    LoadSettings
    
    #Deal with access token lifetime
    $epoch = [int64](([datetime]::UtcNow)-(get-date "1/1/1970")).TotalSeconds
    $accessTokenRemainingLifetime = $script:expireDate - $epoch
    #Refresh the access token if it expire in less than 1 week
    if ($accessTokenRemainingLifetime -le 604800) {
        RefreshAccessToken
    }
    if ($doNotCreate) { LogWarning("Audit Mode!")}
    LogInfo("Starting process")
    StartProcess
    LogInfo("Process finisehd")
    sendEmailUpdate
}