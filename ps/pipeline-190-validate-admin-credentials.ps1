param(
    $dtap,
    $sourcePath,
    $WhatIf
)

###############################################################################
# Dump the parameters
###############################################################################
Write-Verbose ""
Write-Verbose "Dumping parameters:"
Write-Verbose "dtap: $dtap"
Write-Verbose "sourcePath: $sourcePath"

###############################################################################
# Find the sql mi parameter file for the current dtap (custom-development)
###############################################################################
$sqlMiParamFiles = Get-ChildItem -Path $sourcePath -Include azuredeploy.mi-instance.*parameters.json -Recurse
Write-Verbose ""
Write-Verbose "Searching for SQL MI template parameters files."
Write-Verbose "$($sqlMiParamFiles.Count) parameter file(s) found"
Write-Verbose "Listing files:"

# Loop through the configs and find the one.
$sqlMiParamFile = $null
$logMsg = "";
Foreach ($file in $sqlMiParamFiles) {
    $params = ((Get-Content -Raw $file) | ConvertFrom-Json)
    $logMsg = "$($params.parameters.dtap.value) - $file"
    if( $params.parameters.dtap.value -eq "custom-$dtap" ) {
        Write-Host "Found it: $logMsg"
        $item = New-Object -TypeName System.Object
        $item | Add-Member -MemberType NoteProperty -Name Path -Value $file
        $item | Add-Member -MemberType NoteProperty -Name Ring -Value $params.parameters.ring.value
        $sqlMiParamFile = $item
        break
    } else {
        Write-Host "Not the right one: $logMsg"        
    }
}

if (!$sqlMiParamFile) {
    $errorMessage = "Could not find the parameter file for SQL MI"
    Write-Host "$("##vso[task.setvariable variable=ErrorMessage]") $($errorMessage)"
    Write-Error "$($errorMessage)"
    exit 1
}

###############################################################################
# Find the core parameter file for the current dtap
###############################################################################
$coreFiles = Get-ChildItem -Path $sourcePath -Include azuredeploy.core.*parameters.json -Recurse
Write-Verbose ""
Write-Verbose "Searching for core template parameters files."
Write-Verbose "$($coreFiles.Count) parameter file(s) found"
Write-Verbose "Listing files:"

# Loop through the configs and find the one.
$coreFile = $null
$logMsg = "";
Foreach ($file in $coreFiles) {
    $params = ((Get-Content -Raw $file) | ConvertFrom-Json)
    $logMsg = "$($params.parameters.dtap.value) - $file"
    if( $params.parameters.dtap.value -eq $dtap ) {
        Write-Host "Found it: $logMsg"
        $item = New-Object -TypeName System.Object
        $item | Add-Member -MemberType NoteProperty -Name Path -Value $file
        $item | Add-Member -MemberType NoteProperty -Name Ring -Value $params.parameters.ring.value
        $coreFile = $item
    } else {
        Write-Host "Not the right one: $logMsg"        
    }
}

if (!$coreFile) {
    $errorMessage = "Could not find the core parameter file"
    Write-Host "$("##vso[task.setvariable variable=ErrorMessage]") $($errorMessage)"
    Write-Error "$($errorMessage)"
    exit 1
}


###############################################################################
# Get the vault name and the username from the parameter file
###############################################################################
$coreParams = ((Get-Content -Raw $coreFile.Path) | ConvertFrom-Json)
$sqlMiParams = ((Get-Content -Raw $sqlMiParamFile.Path) | ConvertFrom-Json)
$vaultName = $coreParams.parameters.'key-vault-name'.value
$name = $sqlMiParams.parameters.administratorLogin.value

$secret = Get-AzureKeyVaultSecret -VaultName $vaultName -Name $name -ErrorAction SilentlyContinue

if ( !$secret )
{
    $message = "No credentials for $name was found in Azure Key Vault $vaultName"
    $message
    if( $WhatIf -eq $false )
    {
        Write-Host "$("##vso[task.setvariable variable=ErrorMessage]") $($message)"
        Write-Error "$($message)"
        exit 1
    } else {
        Write-Host "$("##vso[task.setvariable variable=WarningMessage]") $($message)"
        Write-Warning "$($message)"
    }
}
exit 0
    