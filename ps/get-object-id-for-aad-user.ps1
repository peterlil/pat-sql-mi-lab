Login-AzureRmAccount
$userFullName = "firstname lastname"
(Get-AzureRmADUser -SearchString $userFullName)