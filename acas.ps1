
param(
    [Parameter(Mandatory = $false, HelpMessage = "Path to the configuration file.")] 
    [alias ('file', 'f')]
    [string]$configFile = $PSScriptRoot + "\settings.ini",

    [Parameter(Mandatory = $false, HelpMessage = "Username to test with the current configuration.")] 
    [alias ('test', 't')]
    [string]$testUser,

    [Parameter(Mandatory = $false)] 
    [alias ('audit', 'a')]
    [switch]$doNotCreate,

    [Parameter(Mandatory = $false)] 
    [alias ('register', 'r')]
    [switch]$registerJob,
    [Parameter(Mandatory = $false)] 
    [alias ('unregister', 'u')]
    [switch]$unregisterJob,

    [Parameter(Mandatory = $false)] 
    [alias ('group', 'g')]
    [switch]$retrieveGroupId,

    [Parameter(Mandatory = $false)] 
    [alias ('help', 'h')]
    [switch]$showHelp
)
$scriptLocation = $PSScriptRoot
$scriptName = "acas.ps1"

###############################################################
######### SCRIPT VARIABLES
###############################################################
$script:adAccountsNumber = 0
$script:acsAccountsNumber = 0
$script:createdAccounts = @()
$script:deletedAccounts = @()
$script:failedAccounts = @()
$script:smtpBody = @()
$script:params = @{}
<#--------------------------------------------------------------
LOAD SETTINGS
--------------------------------------------------------------#>
function CheckEmpty($name, $line) {
    $value = $line.replace("$($name)=","")
    if ($value -like "" -or $value -like $null) {
        Write-Warning  "'$($name)' parameter can't be null. Please correct it and start again. Exiting..." 
        exit 255
    }
    else { return $value.Trim().Trim('"').Trim("'") } 
}
function CheckBool($name, $line) {
    $value = $line.replace("$($name)=","")
    try {$bool = [System.Convert]::ToBoolean($value)}
    catch {
        Write-Error "The only accepted values for the parameter '$($name)' are 'true' or 'false' . Please correct it and start again. Exiting..."
        exit 254
    }
    return $bool
}
function LoadSettings() {
    Write-Host "Loading parameters from $($configFile)"
    Get-Content $configFile | foreach-object -process {
        $line = [regex]::split($_, '#')[0].Trim()
        switch -wildcard ($line) {
            "clientId=*" {$script:params.clientId = CheckEmpty "clientId" $line}
            "clientSecret=*" {$script:params.clientSecret = CheckEmpty "clientSecret" $line}
            "redirectUrl=*" {$script:params.redirectUrl = CheckEmpty "redirectUrl" $line}
            "vpcUrl=*" {$script:params.vpcUrl = CheckEmpty "vpcUrl" $line}
            "validateSslCertificate=*" {$validateSslCertificate = CheckBool "validateSslCertificate" $line}
            "accessToken=*" {$script:params.accessToken = CheckEmpty "accessToken" $line}
            "refreshToken=*" {$script:params.refreshToken = CheckEmpty "refreshToken" $line}
            "expireDate=*" {$script:params.expireDate = CheckEmpty "expireDate" $line}
            "ownerId=*" {$script:params.ownerId = CheckEmpty "ownerId" $line}
            "acsUserGroupId=*" {$script:params.acsUserGroupId = CheckEmpty "acsUserGroupId" $line}
            "acsUserName=*" {$script:params.acsUserName = CheckEmpty "acsUserName" $line}
            "acsEmail=*" {$script:params.acsEmail = CheckEmpty "acsEmail" $line}
            "acsPhone=*" {$script:params.acsPhone = CheckEmpty "acsPhone" $line}
            "acsOrganization=*" {$script:params.acsOrganization = CheckEmpty "acsOrganization" $line}
            "acsDeliveryMethod=*" {
                $value = $line.replace("acsDeliveryMethod=","")
                if ($value -like "NO_DELIVERY" -or $value -like "EMAIL" -or $value -like "SMS" -or $value -like "EMAIL_AND_SMS") {
                    $script:params.acsDeliveryMethod = $value
                }
                else {
                    Write-Error "Wrong 'acsDeliveryMethod' parameter. Please correct it and start again. Exiting..."
                    exit 254
                }
            }
            "adGroup=*" {$script:params.adGroup = CheckEmpty "adGroup" $line}
            "logToAFile=*" {$script:params.logToAFile = CheckBool "logToAFile" $line}
            "logFile=*" {$script:params.logFile = $line.replace("logFile=","")}
            "logToConsole=*" {$script:params.logToConsole = CheckBool "logToConsole" $line}
            "logLevel=*" {
                $value = $line.replace("logLevel=","")
                if ($value -like "debug" -or $value -like "info" -or $value -like "error") {$script:params.logLevel = $value}
                else {
                    Write-Error "Wrong 'logLevel' parameter. Please correct it and start again. Exiting..."
                    exit 254
                }
            }
            "sendEmailUpdate=*" {$script:params.sendEmailUpdate = CheckBool "sendEmailUpdate" $line}
            "smtpServer=*" {$script:params.smtpServer = $line.replace("smtpServer=","")}
            "smtpUserName=*" {$script:params.smtpUserName = $line.replace("smtpUserName=","")}
            "smtpPassword=*" {$smtpPassword = $line.replace("smtpPassword=","")}
            "smtpSecPassword=*" {$script:params.smtpSecPassword = $line.replace("smtpSecPassword=","")}
            "key=*" {$script:params.key = $line.replace("key=","")}
            "smtpTo=*" {$script:params.smtpTo = $line.replace("smtpTo=","")}
            "smtpFrom=*" {$script:params.smtpFrom = $line.replace("smtpFrom=","")}
            "smtpSubject=*" {$script:params.smtpSubject = $line.replace("smtpSubject=","")}
        }
    }

    
    if ($script:params.vpcUrl -like "*.aerohive.com") {
        $script:cloud = $true
    }
    else { 
        $script:cloud = $false  
        if ($validateSslCertificate -like $false) {
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
    if ($script:params.sendEmailUpdate) {
        if ($script:params.smtpSecPassword -like $null) {
            try {
                $script:params.key = New-Object Byte[] 16   # You can use 16, 24, or 32 for AES
                [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($script:params.key)
                $script:params.smtpSecPassword = ConvertTo-SecureString $smtpPassword -AsPlainText -Force | ConvertFrom-SecureString -key $script:params.key
            }
            catch {
                $_
                LogError("It seems the 'smtpPassword' parameter is misconfigured. Please correct it and start again. ")
                exit 250
            }
            $script:params.key = [System.Convert]::ToBase64String($script:params.key)
            SaveSettings
        }
        else {
            try {
                $script:params.key = [System.Convert]::FromBase64String($script:params.key)
                $script:params.smtpSecPassword = ConvertTo-SecureString -String $script:params.smtpSecPassword -key $script:params.key

            }
            catch {LogDebug($_)}
        }
        $script:params.smtpServer = CheckEmpty "smtpServer" $script:params.smtpServer
        $script:params.smtpUserName = CheckEmpty "smtpUserName" $script:params.smtpUserName
        $script:params.smtpCreds = New-Object System.Management.Automation.PSCredential ($script:params.smtpUserName, $script:params.smtpSecPassword)
        $script:params.smtpTo = CheckEmpty "smtpTo" $script:params.smtpTo
        $script:params.smtpFrom = CheckEmpty "smtpFrom" $script:params.smtpFrom
        $script:params.smtpSubject = CheckEmpty "smtpSubject" $script:params.smtpSubject
    }

    $script:headers = @{
        "X-AH-API-CLIENT-SECRET"       = "$($script:params.clientSecret)";
        "X-AH-API-CLIENT-ID"           = "$($script:params.clientId)";
        "X-AH-API-CLIENT-REDIRECT-URI" = "$($script:params.redirectUrl)";
        "Authorization"                = "Bearer $($script:params.accessToken)"
    }
    
    Write-Host "Configuration loaded."
    Write-Host ""
}

function SaveSettings() {
    $settings = @()
    $settingsList = "clientId", "clientSecret", "redirectUrl", "vpcUrl", "accessToken", "refreshToken", "expireDate", "ownerId", "acsUserGroupId", "acsUserName", 
    "acsEmail", "acsPhone", "acsOrganization", "acsDeliveryMethod", "adGroup", "logToAFile", "logFile", "logToConsole", "logLevel", "sendEmailUpdate", "smtpServer", 
    "smtpUserName", "smtpPassword", "smtpSecPassword", "key", "smtpTo", "smtpFrom", "smtpSubject"
    Get-Content $configFile | foreach-object -process {
        $line = $_
        $k = [regex]::split($line, '=')
        # test if the current line is a known parameter
        if ($settingsList -like $k[0]) {
            # generate the line with the current parameter
            $settings += "$($k[0])=$($script:params.$($k[0]))"
            # remove the entry from the array
            $settingsList = $settingsList -notlike $k[0]
            # otherwise, just replace the current line into the setting file
        }
        else { $settings += $line } 
    }
    # test if all the known parameters are present in the setting file
    if ($settingsList.Count -gt 0) {
        # foreach the remaining settings
        foreach ( $item in $settingsList ) {
            # generate the line with the current parameter
            $settings += "$($item)=$($script:params.$($item))"
            # remove the entry from the array
            $settingsList = $settingsList -notlike $k[0]
        }
    }
    $settings | Out-File $configFile
    LogInfo("New settings saved successfully.")
    LogInfo("Reloading settings.")
    LoadSettings
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
    $logstring = "$($date) $($time) ERROR: $($mess)"
    if ($script:params.logToAFile) {Add-content $script:params.logFile -value $logstring}
    if ($script:params.logToConsole) {Write-Host $logstring -ForegroundColor Red}
    if ($script:params.sendEmailUpdate) {$script:smtpBody += $logstring}
}
function LogWarning($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$($date) $($time) WARNING: $($mess)"
    if ($script:params.logToAFile) {Add-content $script:params.logFile -value $logstring}
    if ($script:params.logToConsole) {Write-Host $logstring -ForegroundColor Magenta}
    if ($script:params.sendEmailUpdate) {$script:smtpBody += $logstring}
}
function LogInfo ($mess) {
    if ($script:params.logLevel -like "debug" -or $script:params.logLevel -like "info") {
        $date = Get-Date -Format d
        $time = Get-Date -Format HH:mm:ss.fff
        $logstring = "$($date) $($time) INFO: $($mess)"
        if ($script:params.logToAFile) {Add-content $script:params.logFile -value $logstring}
        if ($script:params.logToConsole) {Write-Host $logstring -ForegroundColor Green}
        if ($script:params.sendEmailUpdate) {$script:smtpBody += $logstring}
    }
}
function LogDebug($mess) {
    if ($script:params.logLevel -like "debug") {
        $date = Get-Date -Format d
        $time = Get-Date -Format HH:mm:ss.fff
        $logstring = "$($date) $($time) DEBUG: $($mess)"
        if ($script:params.logToAFile) {Add-content $script:params.logFile -value $logstring}
        if ($script:params.logToConsole) {Write-Host $logstring -ForegroundColor Gray}
        if ($script:params.sendEmailUpdate) {$script:smtpBody += $logstring}
    }
}
function SendEmailUpdate() {
    if ($script:params.sendEmailUpdate) {
        $c = $script:createdAccounts | Out-String
        $d = $script:deletedAccounts | Out-String
        $f = $script:failedAccounts | Out-String
        $l = $script:smtpBody | Out-String
        $body = @(
            "Number of user accounts (before changes):",
            "Windows Domain: $($script:adAccountsNumber)", 
            "Aerohive: $($script:acsAccountsNumber)",
            "",
            "$($script:createdAccounts.Count) account(s) created:",
            $c ,
            "",
            "$($script:deletedAccounts.Count) account(s) deleted:",
            $d,
            "",
            "$($script:failedAccounts.Count) creation/deletion failed:",
            $f,
            "",
            "Logs:",
            $l
        )
        $body = $body | Out-String
        try {
            Send-MailMessage -To $script:params.smtpTo -From $script:params.smtpFrom -Subject $script:params.smtpSubject -SMTPServer $script:params.smtpServer -Credential $script:params.smtpCreds -Body $body
            LogInfo("Email sent to $($script:params.smtpTo)")            
        }
        catch {
            LogError("Can't send email to $($script:params.smtpTo)")
        }
    }
}
######################################################
######### ACS Requests Functions
######################################################
function AcsRetrieveErrorBody($e) {
    try {
        $result = $e.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        $response = ConvertFrom-Json $responseBody
    }
    catch {
        $response = @{"error" = @{"message" = "Not able to retrieve the message from the server..."}}
    }
    return $response
}
function AcsRetrieveGroupId() {
    LogInfo("Retrieving Aerohive Group Id.")
    try {
        $uri = "https://$($script:params.vpcUrl)/xapi/v1/identity/userGroups?ownerId=$($script:params.ownerId)"
        $response = (Invoke-RestMethod -Uri $uri -Headers $script:headers -Method Get)
    }
    catch {
        LogError("Can't retrieve User Groups from ACS")
        AcsError($_)     
        LogError("Exiting...")
        SendEmailUpdate
        exit 255
    } 
    
    if ($response.data.userGroups) {
        $t = $response.data.userGroups
        $t | Format-Table -AutoSize
    }
    else {
        Write-Host "There is no User Groups here..."
    }
}
function AcsRefreshAccessToken() {
    #Deal with access token lifetime
    $epoch = [int64](([datetime]::UtcNow) - (get-date "1/1/1970")).TotalSeconds
    $accessTokenRemainingLifetime = $script:params.expireDate - $epoch
    #Refresh the access token if it expire in less than 1 week
    if ($accessTokenRemainingLifetime -le 604800) {
        try {
            LogWarning("ACS Access Token will expire in one week. Refreshing it.")
            if ($script:cloud) {
                $uri = "https://cloud.aerohive.com/services/oauth2/token"
            }
            else {
                $uri = "https://$($script:params.vpcUrl)/acct-webapp/services/oauth2/token"
            }
            $body = @{
                "client_secret" = $script:params.clientSecret;
                "client_id"     = $script:params.clientId;
                "grant_type"    = "refresh_token";
                "refresh_token" = $script:params.refreshToken
            }
            $response = (Invoke-RestMethod -Uri $uri -Headers @{"Content-Type" = "application/x-www-form-urlencoded"} -Body $body -Method Post)
            LogInfo("ACS Access Token refreshed. Saving it.")
        }
        catch {
            $err = $_
            LogError("Can't refresh ACS Access Token")
            LogError("Got HTTP$($_.Exception.Response.StatusCode.Value__): $($_.Exception.Response.StatusCode)")
            try {
                $mess = ConvertFrom-Json $_.ErrorDetails.Message
                LogError("Message: $($mess)")
            }
            catch {
                LogError($err)
            }
            LogError("Exiting...")
            SendEmailUpdate
            exit 255
        }
        $expiresIn = $response.expires_in
        $epoch = [int64](([datetime]::UtcNow) - (get-date "1/1/1970")).TotalSeconds
        $expireDate = $epoch + $expiresIn
        if ($response.access_token -notlike $null -and $response.refresh_token -notlike $null) {
            $script:params.accessToken = $($response.access_token)
            $script:params.refreshToken = $($response.refresh_token)
            $script:params.expireDate = $($expireDate)
            SaveSettings
        }
        else {
            Write-Warning "Refresh token failed. Exiting."
            SendEmailUpdate
            exit 254
        }
    }
}
function AcsError($e) {
    if ($e.Exception.Response -like $null) {
        try {    
            LogError("$($e.Exception.Message)")           
        }
        catch {
            LogError($err)
        }  
    }
    else {
        $err = AcsRetrieveErrorBody($e)
        try {    
            LogError("Got HTTP$($e.Exception.Response.StatusCode.value__): $($e.Exception.Response.StatusCode)")
            LogError("Message: $($err.error.message)")           
        }
        catch {
            LogError($err)
        }
    }
}
function AcsGetUsersWithPagination($page, $pageSize) {
    try { 
        $uri = "https://$($script:params.vpcUrl)/xapi/v1/identity/credentials?ownerId=$($script:params.ownerId)&userGroup=$($acsUserGroupId)&page=$($page)&pageSize=$($pageSize)"
        $response = (Invoke-RestMethod -Uri $uri -Headers $script:headers -Method Get)
    }
    catch {   
        $err = $_
        LogError("Can't retrieve Users from ACS")
        AcsError($err)     
        LogError("Exiting...")
        SendEmailUpdate
        exit 255
    } 
    return $response
}
function AcsGetUsers() {
    LogDebug("Retrieving users from ACS.")
    $page = 0
    $pageSize = 1000
    $script:acsAccountsNumber = 0
    $totalCount = 999
    $tempAcsAccounts = @()
    while ($script:acsAccountsNumber -lt $totalCount) {
        $response = AcsGetUsersWithPagination $page $pageSize
        $totalCount = $response.pagination.totalCount
        $script:acsAccountsNumber += $response.pagination.countInPage
        if ($response.data -notlike $null) {
            $tempAcsAccounts += $response.data
            $page ++
        }
        elseif ($response.pagination.totalCount -like 0) {
            $totalCount = 0
        }
        else { 
            SendEmailUpdate
            exit 10 
        }
    }
    LogDebug("$($script:acsAccountsNumber) user(s) retrieved from ACS.")
    return $tempAcsAccounts
}
function AcsCreateAccount($adUser) {
    if ($doNotCreate) {
        LogInfo("CHECK ONLY! The account $($adUser.$($script:params.acsUserName)) should be created" )
    }
    else {
        LogInfo("Creating $($adUser.$($script:params.acsUserName))")
        $acsUser = @{
            "userName"      = $adUser.$($script:params.acsUserName);
            "email"         = $adUser.$($script:params.acsEmail);
            "organization"  = $adUser.$($script:params.acsOrganization);
            "phone"         = $adUser.$($script:params.acsPhone);
            "firstName"     = $adUser.Name;
            "groupId"       = $script:params.acsUserGroupId;
            "deliverMethod" = $script:params.acsDeliveryMethod;
            "policy"        = "PERSONAL";
            "purpose"       = "AD User"
        }
        $json = $acsUser | ConvertTo-Json
        try {
            $uri = "https://$($script:params.vpcUrl)/xapi/v1/identity/credentials?ownerId=$($script:params.ownerId)"
            $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $script:headers -Body $json -ContentType "application/json"
            $script:createdAccounts += $adUser.$($script:params.acsUserName)
        }
        catch {
            LogError("Can't create new user $($adUser.$($script:params.acsUserName))")
            $script:failedAccounts += "Creation of user $($adUser.$($script:params.acsUserName)) failed"
            AcsError($_)            
        }
    }
    return $response
}
function AcsDeleteAccount($acsUser) {
    if ($doNotCreate) {
        LogInfo("CHECK ONLY! The account $($acsUser.userName) with Id $($acsUser.id) should be deleted" )
    }
    else {
        LogInfo("Deleting $($acsUser.userName) with Id $($acsUser.id)")
        $acsUserId = $acsUser.id
        try {
            $uri = "https://$($script:params.vpcUrl)/xapi/v1/identity/credentials?ownerId=$($script:params.ownerId)&ids=$($acsUserId)"
            $response = (Invoke-RestMethod -Uri $uri -Method Delete -Headers $script:headers)
            $script:deletedAccounts += $acsUser.userName
        }
        catch {
            LogError("Can't delete the User $($acsUser.userName)")
            $script:failedAccounts += "Deletion of user $($acsUser.userName) failed"
            AcsError($_)      
        }
        return $response
    }
}

######################################################
######### AD Requests Functions
######################################################
function AdGetUserGroups() {
    LogDebug("Retrieving AD Group details.")
    try {
        $adGroupRetrieved = Get-ADGroup $($script:params.adGroup)
    }
    catch {
        LogError "Can't retrieve the AD Group $($script:params.adGroup)"
        $_
        SendEmailUpdate
        exit 253
    }
    return $adGroupRetrieved
}
function AdGetGroupMembers($adGroup) {
    LogDebug("Retrieving users from the AD group $($adGroup).")
    try {
        $users = Get-ADGroupMember -Recursive -Identity $adGroupRetrieved 
        $script:adAccountsNumber = $users.Count       
    }
    catch {
        LogError "Can't retrieve users from the AD Group $($adGroup)"
        SendEmailUpdate
        exit 252
    }
    LogDebug("$($script:adAccountsNumber) user(s) retrieved from AD.")
    return $users
}
function AdGetUsers() {
    $adAccounts = @()
    $adGroupRetrieved = AdGetUserGroups
    $users = AdGetGroupMembers($adGroupRetrieved)
    foreach ($user in $users) {
        $temp = Get-ADUser -Identity $user.SamAccountName -Properties $script:params.acsUserName, $script:params.acsEmail, $script:params.acsOrganization, $script:params.acsPhone
        if ($temp) { 
            $adAccounts += $temp    
        }
    }
    return $adAccounts
}

function TestUser() {
    $adGroupRetrieved = AdGetUserGroups
    $users = AdGetGroupMembers($adGroupRetrieved)
    $userFound = $false
    foreach ($user in $users) {
        if ($user.SamAccountName -like "$testUser") {
            $userFound = $true
            Get-ADUser -Identity $user.SamAccountName -Properties $script:params.acsUserName, $script:params.acsEmail, $script:params.acsOrganization, $script:params.acsPhone 
        }
    }
    if (-not $userFound) {
        Write-Host "the user $($testUser) is not found."
    }
}

######################################################
######### start process
######################################################
function StartProcess() {
    $acsUsers = AcsGetUsers
    $adUsers = AdGetUsers
    $validAcsUsers = @()
    $i = 0
    foreach ($adUser in $adUsers) {
        $acsAccountExists = $false
        foreach ($acsUser in $acsUsers) {
            if ($adUser.$($script:params.acsUserName) -like $acsUser.userName -And $adUser.Enabled -like "False") {
                $mess = "$($adUser.$($script:params.acsUserName)) is disabled. Should be removed"
                LogDebug($mess)
                AcsDeleteAccount($acsUser)
                break     
            }
            elseif ($adUser.$($script:params.acsUserName) -like $acsUser.userName -And $adUser.Enabled -like "True") {
                $acsAccountExists = $true
                $validAcsUsers += $acsUser
                break
            } 
        }
        if (-not $acsAccountExists) {
            $mess = "$($adUser.$($script:params.acsUserName)) doesn't have any PPSK. Should be created"
            LogDebug($mess)
            AcsCreateAccount($adUser)
        }
        else {
            $mess = "$($adUser.$($script:params.acsUserName)) is enabled and already has a PPSK. nothing to do"
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
            AcsDeleteAccount($acsUser)
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
    if ($id -eq $null) {
        Write-Warning @"

Do not move the script location once registered.
"@
        Write-Warning @"

Currently, the registration process only works from a PowerShell with the adminsitrator rights.
"@
        Write-Host ""
        $response = "x"
        while ($response -notlike "y") {
            $response = Read-Host "Do you want to use the settings.ini file $($configFile) (y/n)?"
            if ($response -like 'n') {
                $fileExists = $false
                while (-not $fileExists) {
                    $configFile = Read-Host "setting.ini location"
                    if (Test-Path $configFile) {
                        $fileExists = $true
                        Write-Host "File found."
                    }
                    else {
                        Write-Host "Can't find the file $($configFile)"
                    }
                }

            }
        }
        $response = "x"
        while ($response -notlike "y" -and $response -notlike "n" ) {
            $response = Read-Host "Do you want to register this script to run it every day (y/n)?"
        }
        if ($response -like "y") {
            $trigger = New-JobTrigger -Daily -At "02:00AM"
            $options = New-ScheduledJobOption -MultipleInstancePolicy StopExisting 
            $scriptPath = Join-Path $scriptLocation $scriptName
            $creds = Get-Credential
            Register-ScheduledJob -Name "ACAS" -File $scriptPath -ArgumentList $configFile -Trigger $trigger -Credential $creds -ScheduledJobOption $options -RunNow
        } else {Write-Host "Nothing done."}
    }
    else {
        Write-Warning "This script is already registered."
        Write-Warning "Please unregister it first with the '$($scriptName) -u' command"
        Write-Host ""
        Get-ScheduledJob $id
    }
}
function Unregister() {
    Write-Host "Check if the task is running."
    $runningJob = (Get-Job -Name ACAS -ErrorAction SilentlyContinue)
    if ($runningJob -notlike $null) {
        $runningJob
        foreach ($job in $runningJob) {
            Write-Host "Trying to stop the running task $($job.Id)."
            Stop-Job $job.Id
            Remove-Job $job.Id
        }
    }
    else {
        Write-Host "This task is currently stopped."
    }
    Write-Host ""
    Write-Host "Check if the task is registered."
    $scheduledJob = (Get-ScheduledJob -Name ACAS -ErrorAction SilentlyContinue)
    if ($scheduledJob -notlike $null) {
        $scheduledJob
        Write-Host ""
        $response = "x"
        while ($response -notlike "y" -and $response -notlike "n" ) {
            $response = Read-Host "Do you want to unregister this script (y/n)?"
        }
        if ($response -like "y") {
            Write-Host "Trying to unregisterd the task $($job.Id)."
            try {
                Get-ScheduledTask -TaskName "ACAS" | Unregister-ScheduledTask -Confirm:$false
                Write-Host "ScheduleJob unregistered."
            }
            catch {
                $_
                Write-Host "Not able to unregsiter the task."
            }
        }
        else {Write-Host "Nothing done."}
    }
    else {
        Write-Host "Not able to find the scheduledJob ACAS."
    }
}
######################################################
######### usage
######################################################
function Usage() {
    $usage = @"
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
    AcsRefreshAccessToken
    AcsRetrieveGroupId
}
else {
    LoadSettings
    AcsRefreshAccessToken
    if ($doNotCreate) { LogWarning("Audit Mode!")}
    LogInfo("Starting process")
    StartProcess
    LogInfo("Process finished")
    SendEmailUpdate
}
