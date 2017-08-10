<#--------------------------------------------------------------
 application credentials
 These information 
--------------------------------------------------------------#>
$clientId="xxxxxx"
$clientSecret="xxxxxx"
$redirectUrl="https://xxxxxx"

<#--------------------------------------------------------------
ACS account parameters
--------------------------------------------------------------#>
$vpcUrl="cloud-ie.aerohive.com"
$accessToken="Z83CvGzqTco-6O1uAsJuoTRsWf_Y8zBXf4d129a2"
$refreshToken="tm7Hku_khmmjQN2uDMtEF1Az78f0SfKJ"
$expireDate=0
$ownerId=34515

<#--------------------------------------------------------------
 WiFi account parameters
--------------------------------------------------------------#>
# User Group
$acsUserGroupId = xxxxxxxx
# bindings between ACS and AD parameters
$acsUserName = "SamAccountName"
$acsEmail = "UserPrincipalName"
#AD phone property can be "MobilePhone", "OfficePhone" or "HomePhone"
$acsPhone = "OfficePhone"
$acsOrganization = "Organization"
# may be 'NO_DELIVERY', 'EMAIL', 'SMS' or 'EMAIL_AND_SMS'
$acsDeliveryMethod = "EMAIL_AND_SMS"
<#--------------------------------------------------------------
 AD Group: the script will create a Wi-Fi account for every 
 user belonging to this Group 
--------------------------------------------------------------#>
$adGroup="Domain Admins"
<#--------------------------------------------------------------
Logging parameters
--------------------------------------------------------------#>
$logFile="C:\Users\tmunzer.AH-LAB\Desktop\acs.log"
$logToAFile = $true
$logToConsole = $true



<#--------------------------------------------------------------
SCRIPT
--------------------------------------------------------------#>
$headers=@{
    "X-AH-API-CLIENT-SECRET"="$clientSecret";
    "X-AH-API-CLIENT-ID"="$clientId";
    "X-AH-API-CLIENT-REDIRECT-URI"="$redirectUrl";
    "Authorization"="Bearer $accessToken"
}

###############################################################
######### LOGGING
###############################################################
function Log-Error ($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$date $time ERROR: $mess"
    if ($logToAFile) {Add-content $Logfile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Red}
}
function Log-Info ($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$date $time INFO: $mess"
    if ($logToAFile) {Add-content $Logfile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Green}
}
function Log-Debug($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$date $time DEBUG: $mess"
    if ($logToAFile) {Add-content $Logfile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Gray}
}

######################################################
######### ACS Requests Functions
######################################################
function GetUsersFromAcs {
    try { 
        $response = Invoke-RestMethod -Uri "https://$vpcUrl/xapi/v1/identity/credentials?ownerId=$ownerId&userGroup=$acsUserGroupId" -Headers $headers 
    } catch { 
        $err = $_.Exception
        Log-Error("Can't retrieve Users from ACS")
        Log-Error($err.Message)
        Log-Error("Exiting...")
        exit 255
    } 
        
    return $response.data
}

function CreateAcsAccount($adUser){
    Log-Info("Creating " + $adUser.$acsUserName)
    $acsUser=@{
        "userName"=$adUser.$acsUserName;
        "email"= $adUser.$acsEmail;
        "organization"= $adUser.$acsOrganization;
        "phone"= $adUser.$acsPhone;
        "firstName"= $acsUser.Name;
        "groupId"= $acsUserGroupId;
        "deliverMethod"= $acsDeliveryMethod;
        "policy"= "PERSONAL";
        "purpose"= "AD User"
    }
    $json = $acsUser | ConvertTo-Json
    try {
        $response = Invoke-RestMethod -Uri "https://$vpcUrl/xapi/v1/identity/credentials?ownerId=$ownerId" -Method Post -Headers $headers -Body $json -ContentType "application/json"
    } catch {
        $err = $_.Exception
        $mess = "Can't create new User " + $adUser.$acsUserName
        $acsUserToJson = ConvertTo-Json $acsUser
        Log-Error($mess)
        Log-Error($acsUserToJson)
        Log-Error($err.Message)
    }
    return $response
}

function DeleteAcsAccount($acsUser){
    Log-Info("Deleting " + $acsUser.userName + " with Id " + $acsUser.id)
    $acsUserId = $acsUser.id
    try {
        $response = Invoke-RestMethod -Uri "https://$vpcUrl/xapi/v1/identity/credentials?ownerId=$ownerId&ids=$acsUserId" -Method Delete -Headers $headers
    } catch {
        $err = $_.Exception
        Log-Error("Can't delete the User " + $acsUser.userName)
        Log-Error($err.Message)
    }
    return $response
}

######################################################
######### AD Requests Functions
######################################################
function GetUsersFromAd {
    $adAccounts = @()

    $users = Get-ADGroupMember $adGroup -Recursive 
    foreach ($user in $users)
    {
        $temp = Get-ADUser $user.SamAccountName -Properties $acsUserName,$acsEmail,$acsOrganization,$acsPhone
        if ($temp) { 
            $adAccounts += $temp    
        }
    }
    return $adAccounts
}

######################################################
######### Entry point
######################################################

$acsUsers = GetUsersFromAcs
$adUsers = GetUsersFromAd
$validAcsUsers = @()
foreach ($adUser in $adUsers)
{
    $acsAccountExists = $false
    foreach ($acsUser in $acsUsers) {
        if ($adUser.$acsUserName -like $acsUser.userName -And $adUser.Enabled -like "False") {
            $mess = $adUser.$acsUserName + " is disabled. Should be removed"
            Log-Debug($mess)
            DeleteAcsAccount($acsUser)
            break     
        } elseif ($adUser.$acsUserName -like $acsUser.userName -And $adUser.Enabled -like "True") {
            $acsAccountExists = $true
            $validAcsUsers += $acsUser
            break
        } 
    }
    if (-not $acsAccountExists) {
        $mess = $adUser.$acsUserName + " doesn't have any PPSK. Should be created"
        Log-Debug($mess)
        CreateAcsAccount($adUser)
    } else {
        $mess = $adUser.$acsUserName + " is enabled and already has a PPSK. nothing to do"
        Log-Debug($mess)
    }
}

foreach ($acsUser in $acsUsers) {
    if ( $validAcsUsers -notcontains $acsUser) {
        $mess= $acsUSer.userName + " should be removed because it does not belong to the AD"
        Log-Debug($mess)
        DeleteAcsAccount($acsUser)
    }
}
