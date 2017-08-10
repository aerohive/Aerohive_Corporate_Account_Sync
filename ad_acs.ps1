<#--------------------------------------------------------------
LOAD SETTINGS
--------------------------------------------------------------#>
$settings=$PSScriptRoot + "\settings.ini"
Get-Content $settings | foreach-object -begin {$params=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True) -and ($k[0].StartsWith('#') -ne $True)) { $params.Add($k[0], $k[1].Trim()) } }

$clientId=$params.clientId
$clientSecret=$params.clientSecret
$redirectUrl=$params.redirectUrl
$vpcUrl=$params.vpcUrl
$accessToken=$params.accessToken
$refreshToken=$params.refreshToken
$expireDate=$params.expireDate
$ownerId=$params.ownerId
$acsUserGroupId = $params.acsUserGroupId
$acsUserName = $params.acsUserName.ToString()
$acsEmail = $params.acsEmail
$acsPhone = $params.acsPhone
$acsOrganization = $params.acsOrganization
$acsDeliveryMethod = $params.acsDeliveryMethod
$adGroup=$params.adGroup
$logFile=$params.logFile
$logToAFile=$params.logToAFile
$logToConsole=$params.logToConsole


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
    if ($logToAFile) {Add-content $logFile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Red}
}
function Log-Info ($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$date $time INFO: $mess"
    if ($logToAFile) {Add-content $logFile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Green}
}
function Log-Debug($mess) {
    $date = Get-Date -Format d
    $time = Get-Date -Format HH:mm:ss.fff
    $logstring = "$date $time DEBUG: $mess"
    if ($logToAFile) {Add-content $logFile -value $logstring}
    if ($logToConsole) {Write-Host $logstring -ForegroundColor Gray}
}

######################################################
######### ACS Requests Functions
######################################################
function AcsError($data){
        Log-Error("Got HTTP" + $data.error.status + ": "+$data.error.code)
        Log-Error("Message: " + $data.error.message)
}
function GetUsersFromAcs() {
    try { 
        $response = (Invoke-RestMethod -Uri "https://$vpcUrl/xapi/v1/identity/credentials?ownerId=$ownerId&userGroup=$acsUserGroupId" -Headers $headers -Method Get)
    } catch {   
        Log-Error("Can't retrieve Users from ACS")
        AcsError(ConvertFrom-Json $_.ErrorDetails.Message)
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
        Log-Error("Can't create new User " + $adUser.$acsUserName)
        AcsError(ConvertFrom-Json $_.ErrorDetails.Message)
    }
    return $response
}

function DeleteAcsAccount($acsUser){
    Log-Info("Deleting " + $acsUser.userName + " with Id " + $acsUser.id)
    $acsUserId = $acsUser.id
    try {
        $response = Invoke-RestMethod -Uri "https://$vpcUrl/xapi/v1/identity/credentials?ownerId=$ownerId&ids=$acsUserId" -Method Delete -Headers $headers
    } catch {
        Log-Error("Can't delete the User " + $acsUser.userName)
        AcsError(ConvertFrom-Json $_.ErrorDetails.Message)
    }
    return $response
}

######################################################
######### AD Requests Functions
######################################################
function GetUsersFromAd() {
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
$i=0
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
    $i++
    $percentage = (($i / $adUsers.length)  * 100)
    Write-Progress -activity "Checking AD Users" -status "Progress: " -PercentComplete $percentage  -CurrentOperation "$percentage%"
  Start-Sleep 1

}


$i = 0
foreach ($acsUser in $acsUsers) {
    if ( $validAcsUsers -notcontains $acsUser) {
        $mess= $acsUSer.userName + " should be removed because it does not belong to the AD"
        Log-Debug($mess)
        DeleteAcsAccount($acsUser)
    }
    $i++
    $percentage = (($i / $acsUsers.length)  * 100)
    Write-Progress -activity "Checking Aerohive Users" -status "Progress: " -PercentComplete $percentage  -CurrentOperation "$percentage%"
}
