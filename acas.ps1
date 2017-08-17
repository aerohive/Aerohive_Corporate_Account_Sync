
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
$scriptName="acas.ps1"

<#--------------------------------------------------------------
LOAD SETTINGS
--------------------------------------------------------------#>
function checkEmpty($name, $value){
    if ($value -like ""){
        Write-Warning  "'$($name)' parameter can't be null. Please correct it and start again. Exiting..." 
        exit 255
    } else { return $value.Trim().Trim('"').Trim("'") } 
}
function checkBool($name, $value){
    try {$bool = [System.Convert]::ToBoolean($value)}
    catch {
        Write-Error "The only accepted values for the parameter '$($name)' are 'true' or 'false' . Please correct it and start again. Exiting..."
        exit 254
    }
    return $bool
}
function LoadSettings(){
    Write-Host "Loading parameters from $($configFile)"
    Get-Content $configFile | foreach-object -process {
        $k = [regex]::split($_, '=')
        switch ($k[0]){
            "clientId"                  {$script:clientId = checkEmpty "clientId" $k[1]}
            "clientSecret"              {$script:clientSecret = checkEmpty "clientSecret" $k[1]}
            "redirectUrl"               {$script:redirectUrl = checkEmpty "redirectUrl" $k[1]}
            "vpcUrl"                    {$script:vpcUrl = checkEmpty "vpcUrl" $k[1]}
            "validateSslCertificate"    {$script:validateSslCertificate = checkBool "validateSslCertificate" $k[1]}
            "accessToken"               {$script:accessToken = checkEmpty "accessToken" $k[1]}
            "refreshToken"              {$script:refreshToken = checkEmpty "refreshToken" $k[1]}
            "expireDate"                {$script:expireDate = checkEmpty "expireDate" $k[1]}
            "ownerId"                   {$script:ownerId = checkEmpty "ownerId" $k[1]}
            "acsUserGroupId"            {$script:acsUserGroupId = checkEmpty "acsUserGroupId" $k[1]}
            "acsUserName"               {$script:acsUserName = checkEmpty "acsUserName" $k[1]}
            "acsEmail"                  {$script:acsEmail = checkEmpty "acsEmail" $k[1]}
            "acsPhone"                  {$script:acsPhone = checkEmpty "acsPhone" $k[1]}
            "acsOrganization"           {$script:acsOrganization = checkEmpty "acsOrganization" $k[1]}
            "acsDeliveryMethod" {
                if ($k[1] -like "NO_DELIVERY" -or $k[1] -like "EMAIL" -or $k[1] -like "SMS" -or $k[1] -like "EMAIL_AND_SMS") {
                    $script:acsDeliveryMethod = $k[1]
                } else {
                    Write-Error "Wrong 'acsDeliveryMethod' parameter. Please correct it and start again. Exiting..."
                    exit 254
                }}
            "adGroup"                   {$script:adGroup = checkEmpty "adGroup" $k[1]}
            "logToAFile"                {$script:logToAFile = checkBool "logToAFile" $k[1]}
            "logFile"                   {$script:logFile = $k[1]}
            "logToConsole"              {$script:logToConsole = checkBool "logToConsole" $k[1]}
            "logLevel" {
                if ($k[1] -like "debug" -or $k[1] -like "info" -or $k[1] -like "error") {$script:logLevel = $k[1]}
                else {
                    Write-Error "Wrong 'logLevel' parameter. Please correct it and start again. Exiting..."
                    exit 254
                }
            }
            "sendEmailUpdate"           {$script:sendEmailUpdate = checkBool "sendEmailUpdate" $k[1]}
            "smtpServer"                {$script:smtpServer = $k[1]}
            "smtpUserName"              {$script:smtpUserName = $k[1]}
            "smtpPassword"              {$smtpPassword = $k[1]}
            "smtpTo"                    {$script:smtpTo = $k[1]}
            "smtpFrom"                  {$script:smtpFrom = $k[1]}
            "smtpSubject"               {$script:smtpSubject = $k[1]}
        }
    }

    
    if ($script:vpcUrl -like "*.aerohive.com") {
        $script:cloud = $true
    } else { 
        $script:cloud = $false
        if ($validateSslCertificate -like $false -and $validateSslCertificate -notlike $null) {
            add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy         
        }
    }
    if ($script:sendEmailUpdate) {
        $script:smtpServer=checkEmpty "smtpServer" $script:smtpServer
        $script:smtpUserName=checkEmpty "smtpUserName" $script:smtpUserName
        $secpasswd = ConvertTo-SecureString $smtpPassword -AsPlainText -Force
        $script:smtpCreds = New-Object System.Management.Automation.PSCredential ($script:smtpUserName, $secpasswd)
        $script:smtpTo=checkEmpty "smtpTo" $script:smtpTo
        $script:smtpFrom=checkEmpty "smtpFrom" $script:smtpFrom
        $script:smtpSubject=checkEmpty "smtpSubject" $script:smtpSubject
    }

    $script:headers = @{
        "X-AH-API-CLIENT-SECRET"       = "$($script:clientSecret)";
        "X-AH-API-CLIENT-ID"           = "$($script:clientId)";
        "X-AH-API-CLIENT-REDIRECT-URI" = "$($script:redirectUrl)";
        "Authorization"                = "Bearer $($accessToken)"
    }
    
    Write-Host "Configuration loaded."
    Write-Host ""
}
<#--------------------------------------------------------------
SCRIPT
--------------------------------------------------------------#>
###############################################################
######### SCRIPT VARIABLES
###############################################################
$script:adAccountsNumber=0
$script:acsAccountsNumber=0
$script:createdAccounts=@()
$script:deletedAccounts=@()
$script:smtpBody=@()
###############################################################
######### LOGGING
###############################################################
function LogError($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$($date) $($time) ERROR: $($mess)"
    if ($script:logToAFile) {Add-content $script:logFile -value $logstring}
    if ($script:logToConsole) {Write-Host $logstring -ForegroundColor Red}
    if ($script:sendEmailUpdate) {$script:smtpBody += $logstring}
}
function LogWarning($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$($date) $($time) WARNING: $($mess)"
    if ($script:logToAFile) {Add-content $script:logFile -value $logstring}
    if ($script:logToConsole) {Write-Host $logstring -ForegroundColor Magenta}
    if ($script:sendEmailUpdate) {$script:smtpBody += $logstring}
}
function LogInfo ($mess) {
    if ($script:logLevel -like "debug" -or $script:logLevel -like "info") {
        $date = Get-Date -Format d
        $time = Get-Date -Format HH:mm:ss.fff
        $logstring = "$($date) $($time) INFO: $($mess)"
        if ($script:logToAFile) {Add-content $script:logFile -value $logstring}
        if ($script:logToConsole) {Write-Host $logstring -ForegroundColor Green}
        if ($script:sendEmailUpdate) {$script:smtpBody += $logstring}
    }
}
function LogDebug($mess) {
    if ($script:logLevel -like "debug") {
        $date = Get-Date -Format d
        $time = Get-Date -Format HH:mm:ss.fff
        $logstring = "$($date) $($time) DEBUG: $($mess)"
        if ($script:logToAFile) {Add-content $script:logFile -value $logstring}
        if ($script:logToConsole) {Write-Host $logstring -ForegroundColor Gray}
        if ($script:sendEmailUpdate) {$script:smtpBody += $logstring}
    }
}
function sendEmailUpdate(){
    if ($script:sendEmailUpdate) {
        $c = $script:createdAccounts | Out-String
        $d = $script:deletedAccounts | Out-String
        $l = $script:smtpBody | Out-String
        $body=@(
            "Number of user accounts (before changes):",
            "Windows Domain: $($script:adAccountsNumber)", 
            "Aerohive: $($script:acsAccountsNumber)",
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
        Send-MailMessage -To $script:smtpTo -From $script:smtpFrom -Subject $script:smtpSubject -SMTPServer $script:smtpServer -Credential $script:smtpCreds -Body $body
    }
}
######################################################
######### ACS Requests Functions
######################################################
function RetrieveGroupId(){
    LogInfo("Retrieving Aerohive Group Id.")
    try {
        $uri = "https://$($script:vpcUrl)/xapi/v1/identity/userGroups?ownerId=$($script:ownerId)"
        $response = (Invoke-RestMethod -Uri $uri -Headers $script:headers -Method Get)
    } catch {
        $err = $_
        LogError("Can't retrieve User Groups from ACS")
        try {
            AcsError(ConvertFrom-Json $_.ErrorDetails.Message)            
        } catch {
            LogError($err)
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
    #Deal with access token lifetime
    $epoch = [int64](([datetime]::UtcNow)-(get-date "1/1/1970")).TotalSeconds
    $accessTokenRemainingLifetime = $script:expireDate - $epoch
    #Refresh the access token if it expire in less than 1 week
    if ($accessTokenRemainingLifetime -le 604800) {
        try {
            LogWarning("ACS Access Token will expire in one week. Refreshing it.")
            if ($script:cloud) {
                $uri = "https://cloud.aerohive.com/services/oauth2/token"
            } else {
                $uri = "https://$($script:vpcUrl)/acct-webapp/services/oauth2/token"
            }
            $body = @{
                "client_secret"=$script:clientSecret;
                "client_id"=$script:clientId;
                "grant_type"="refresh_token";
                "refresh_token"=$refreshToken
            }
            $response = (Invoke-RestMethod -Uri $uri -Headers @{"Content-Type" = "application/x-www-form-urlencoded"} -Body $body -Method Post)
            LogInfo("ACS Access Token refreshed. Saving it.")
        } catch {
            $err = $_
            LogError("Can't refresh ACS Access Token")
            LogError("Got HTTP$($_.Exception.Response.StatusCode.Value__): $($_.Exception.Response.StatusCode)")
            try {
                $mess = ConvertFrom-Json $_.ErrorDetails.Message
                LogError("Message: $($mess)")
            } catch {
                LogError($err)
            }
            LogError("Exiting...")
            exit 255
        }
        $expiresIn = $response.expires_in
        $epoch = [int64](([datetime]::UtcNow)-(get-date "1/1/1970")).TotalSeconds
        $expireDate = $epoch + $expiresIn
        if ($response.access_token -notlike $null -and $response.refresh_token -notlike $null){
            $settings = 
@"
"@
            Get-Content $configFile | foreach-object -process {
                $line = $_
                $newLine = ""
                switch -wildcard ($line) {
                    "accessToken=*" { $newLine = "accessToken=$($response.access_token)" }
                    "refreshToken=*" { $newLine = "refreshToken=$($response.refresh_token)" }
                    "expireDate=*" { $newLine = "expireDate=$($expireDate)" }
                    Default { $newLine = $line}
                }
                $settings += 
@"
$($newLine.trim())

"@
            }
            $settings | Out-File $configFile
            LogInfo("New ACS Access Token saved successfully.")
            LogInfo("Reloading settings.")
            LoadSettings
        } else {
            Write-Warning "Refresh token failed. Exiting."
            exit 254
        }
    }
}

function AcsError($data) {
    LogError("Got HTTP$($data.error.status): $($data.error.code)")
    LogError("Message: $($data.error.message)")
}
function GetUsersFromAcsPagination($page, $pageSize){
    try { 
        $uri = "https://$($script:vpcUrl)/xapi/v1/identity/credentials?ownerId=$($script:ownerId)&userGroup=$($acsUserGroupId)&page=$($page)&pageSize=$($pageSize)"
        $response = (Invoke-RestMethod -Uri $uri -Headers $script:headers -Method Get)
    }
    catch {   
        $err = $_
        LogError("Can't retrieve Users from ACS")
        try {
            AcsError(ConvertFrom-Json $_.ErrorDetails.Message)            
        } catch {
            LogError($err)
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
        if ($response.data -notlike $null){
            $tempAcsAccounts += $response.data
            $page ++
        } elseif ($response.pagination.totalCount -like 0){
            $totalCount = 0
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
            $uri = "https://$($script:vpcUrl)/xapi/v1/identity/credentials?ownerId=$($script:ownerId)"
            $response = (Invoke-RestMethod -Uri $uri -Method Post -Headers $script:headers -Body $json -ContentType "application/json")
            $script:createdAccounts += $adUser.$acsUserName
        }
        catch {
            $err = $_
            LogError("Can't create new User $($adUser.$acsUserName)")
            try {
                AcsError(ConvertFrom-Json $_.ErrorDetails.Message)            
            } catch {
                LogError($err)
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
        $script:acsUserId = $acsUser.id
        try {
            $uri = "https://$($script:vpcUrl)/xapi/v1/identity/credentials?ownerId=$($script:ownerId)&ids=$($script:acsUserId)"
            $response = (Invoke-RestMethod -Uri $uri -Method Delete -Headers $script:headers)
            $script:deletedAccounts += $acsUser.userName
        }
        catch {
            $err = $_
            LogError("Can't delete the User $($acsUser.userName)")
            try {
                AcsError(ConvertFrom-Json $_.ErrorDetails.Message)            
            } catch {
                LogError($err)
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
    RefreshAccessToken
    RetrieveGroupId
}
else {
    LoadSettings
    RefreshAccessToken
    if ($doNotCreate) { LogWarning("Audit Mode!")}
    LogInfo("Starting process")
    StartProcess
    LogInfo("Process finisehd")
    sendEmailUpdate
}