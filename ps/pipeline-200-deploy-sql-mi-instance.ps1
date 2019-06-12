param (
    $dtap,
    $sourcePath,
    $SourceVersion,
    $WhatIf
)

function Format-ValidationOutput {
    param ($ValidationOutput, [int] $Depth = 0)
    Set-StrictMode -Off
    return @($ValidationOutput | Where-Object { $_ -ne $null } | ForEach-Object { @("  " * $Depth + $_.Code + ": " + $_.Message) + @(Format-ValidationOutput @($_.Details) ($Depth + 1)) })
}

function Get-ObjectMembers {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [PSCustomObject]$obj
    )
    $obj | Get-Member -MemberType NoteProperty | ForEach-Object {
        $key = $_.Name
        [PSCustomObject]@{Key = $key; Value = $obj."$key".value}
    }
}

function deployTemplate($fullPath, $SourceVersion, $administratorLoginPassword) {
    ###############################################################################
    # Deploy a template
    ###############################################################################

    # Regular expressions patterns
    $pathNoFilenameRegexPattern = "[\w\s\-@.\\:]+(?=azuredeploy.mi-instance[\w\s\-.]*.parameters.json$)"
    $jsonParamFileRegexPattern = "azuredeploy.mi-instance[\w\s\-.]*.parameters.json$"
    $rgNamePattern = "(?<=resource-groups\\)[\w\s-.]+"

    $path = [System.Text.RegularExpressions.Regex]::Match($fullPath, $pathNoFilenameRegexPattern).Value
    Write-Verbose ""
    Write-Verbose "Deployment of $($fullPath)"
    Write-Verbose "Path: $($path)"
    $jsonParameterFileName = [System.Text.RegularExpressions.Regex]::Match($fullPath, $jsonParamFileRegexPattern).Value
    $jsonParameterFullFileName = "$($path)$($jsonParameterFileName)"
    Write-Verbose "Template parameters filename: $($jsonParameterFileName)"
    Write-Verbose "Template parameters full filename: $($jsonParameterFullFileName)"
    
    $rgName = [System.Text.RegularExpressions.Regex]::Match($fullPath, $rgNamePattern).Value
    Write-Verbose "Resource Group Name: $($rgName)"
    $jsonTemplateFileName = $path + ($jsonParameterFileName.ToLower().Replace(".development.", ".").Replace(".dev.", ".").Replace(".test.", ".").Replace(".uat.", ".").Replace(".acc.", ".").Replace(".production.", ".").Replace(".prod.", ".").Replace(".parameters.", "."))
    Write-Verbose "Template file name: $($jsonTemplateFileName)"

    # Load the parameter file and set parameter(s)
    $params = ((Get-Content -Raw $fullPath) | ConvertFrom-Json)
    $location = $params.parameters.location.value

    # Make sure the resource group exists
    Write-Verbose "Checking if Resource Group $($rgName) exists"
    $rg = Get-AzureRmResourceGroup -Name $rgName -ErrorAction SilentlyContinue
    if($rg) {
        Write-Host "Resource group $($rgName) already exists, no need to create."
    } else {
        Write-Host "Creating resource group $($rgName)"
        $rg = New-AzureRmResourceGroup -Name $rgName -Location $location -ErrorAction Stop
    }
    Write-Verbose $jsonTemplateFileName
    Write-Verbose $jsonParameterFullFileName

    # Prepare the TemplateParameterObject
    $dynamicParams = @{
        administratorLoginPassword = $administratorLoginPassword
    }
    $params.parameters | Get-ObjectMembers | ForEach-Object {
        $dynamicParams.Add($_.Key, $_.value)
    }
    
    $ErrorMessages = @()
    if ($WhatIf -eq $true) {
        $ErrorMessages = Format-ValidationOutput ( Test-AzureRmResourceGroupDeployment `
            -ResourceGroupName $rgName `
            -TemplateFile $jsonTemplateFileName `
            -TemplateParameterObject $dynamicParams `
            -Verbose)
    } else {
        $deployName = "$($rgName)-$($SourceVersion)"
        New-AzureRmResourceGroupDeployment -Name $deployName `
            -ResourceGroupName $rgName `
            -Mode Incremental `
            -TemplateFile $jsonTemplateFileName `
            -TemplateParameterObject $dynamicParams `
            -Force `
            -Verbose `
            -ErrorVariable ErrorMessages

    }

    if ($ErrorMessages)
    {
        ("##vso[task.setvariable variable=ErrorMessage] {0}" -f ($ErrorMessages -Join "; ") )
        Write-Error "$($ErrorMessages -Join "; ")"
        exit 1
    }
}

###############################################################################
# Dump the parameters
###############################################################################
Write-Verbose ""
Write-Verbose "Dumping parameters:"
Write-Verbose "dtap: $dtap"
Write-Verbose "sourcePath: $sourcePath"
Write-Verbose "SourceVersion: $SourceVersion"
Write-Verbose "WhatIf: $WhatIf"

###############################################################################
# Find the sqm mi parameter files for the current dtap (custom-development)
###############################################################################
$sqlMiParamFiles = Get-ChildItem -Path $sourcePath -Include azuredeploy.mi-instance.*parameters.json -Recurse
Write-Verbose ""
Write-Verbose "Searching for SQL MI template parameters files."
Write-Verbose "$($sqlMiParamFiles.Count) parameter file(s) found. Validating correct dtap."

# Loop through the configs and find the one.
$parameterFile = $null
$logMsg = "";
Foreach ($file in $sqlMiParamFiles) {
    $params = ((Get-Content -Raw $file) | ConvertFrom-Json)
    $logMsg = "$($params.parameters.dtap.value) - $($file.FullName)"
    if( $params.parameters.dtap.value -eq "custom-$dtap" ) {
        Write-Host "To deploy: $logMsg"
        $parameterFile = $file.FullName
        break
    } else {
        Write-Host "Not to deploy: $logMsg"        
    }
}

if (!$parameterFile) {
    $errorMessage = "No parameter file found. Nothing to deploy."
    ("##vso[task.setvariable variable=ErrorMessage] {0}" -f $errorMessage )
    Write-Error $errorMessage
    exit 1
}

 
###############################################################################
# Get the credentials from Azure Key Vault
###############################################################################

# Get the name of the Key Vault secret (= name of login)
$params = ((Get-Content -Raw $parameterFile) | ConvertFrom-Json)
$secretName = $params.parameters.administratorLogin.value
if( !$secretName -or $secretName.Length -eq 0 ) {
    $errorMessage = "Secret name not found in parameter file $parameterFile. Aborting"
    ("##vso[task.setvariable variable=ErrorMessage] {0}" -f $errorMessage )
    Write-Error $errorMessage
    exit 1
}

$vaultName = $params.parameters.'key-vault-name'.value
if( !$vaultName -or $vaultName.Length -eq 0 ) {
    $errorMessage = "Azure Key Vault name not found in parameter file $parameterFile. Aborting"
    ("##vso[task.setvariable variable=ErrorMessage] {0}" -f $errorMessage )
    Write-Error $errorMessage
    exit 1
}

$secret = (Get-AzureKeyVaultSecret -VaultName $vaultName -Name $secretName -ErrorAction SilentlyContinue)

###############################################################################
# Deploy
###############################################################################

Write-Host "Create deployment for $parameterFile"

$jsonParamFileRegexPattern = "azuredeploy.mi-instance[\w\s-.]*.parameters.json$"
#$lastDirRegexPattern = "[\w\s-.]+(?=\\azuredeploy[\w\s-.]*.parameters.json$)"
$rgNamePattern = "(?<=resource-groups\\)[\w\s-.]+"
$pathNoFilenameRegexPattern = "[\w\s-.\\:]+(?=azuredeploy.mi-instance[\w\s-.]*.parameters.json$)"

deployTemplate -fullPath $parameterFile -SourceVersion $SourceVersion -administratorLoginPassword $secret.SecretValue

