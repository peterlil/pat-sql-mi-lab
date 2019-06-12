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

function deployTemplate($fullPath, $SourceVersion) {
    ###############################################################################
    # Deploy a template
    ###############################################################################

    # Regular expressions patterns
    $pathNoFilenameRegexPattern = "[\w\s-.@\\:]+(?=azuredeploy[\w\s-.]*.parameters.json$)"
    $jsonParamFileRegexPattern = "azuredeploy[\w\s-.]*.parameters.json$"
    $rgNamePattern = "(?<=resource-groups\\)[\w\s-.]+"

    $path = [System.Text.RegularExpressions.Regex]::Match($fullPath, $pathNoFilenameRegexPattern).Value
    Write-Verbose "##########################################################################################"
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
    $pfContent = (Get-Content -Raw $fullPath) # pf = Parameter File

    #$pfContent #debug
    
    # Loop through, find all macros and parse them
    $reFindMacros = "(?<="")#[\w\s/\[\]#-.]+#(?="")"
    $parsedMacros = @()
    $matches = [System.Text.RegularExpressions.Regex]::Matches($pfContent, $reFindMacros)
    $matches | ForEach-Object {
        #$_.Value #debug
        $macro = New-Macro -Unparsed $_.Value
        ParseMacro ([ref]$macro)
        #$macro | format-list * #debug
        $parsedMacros += $macro
    }
    
    # Replace all macros
    $parsedMacros | ForEach-Object {
        $pfContent = $pfContent.Replace($_.Unparsed, $_.Parsed)
    }
    
    # Convert final parameter file to json object
    $params = ($pfContent | ConvertFrom-Json)
    if(!$params) {
        Write-Error "Something went wrong. Terminating."
        exit
    }

     # Prepare the TemplateParameterObject
     $dynamicParams = @{ }
    $params.parameters | Get-ObjectMembers | ForEach-Object {
        $dynamicParams.Add($_.Key, $_.value)
    }

    # Make sure the resource group exists
    $location = $params.parameters.location.value
    Write-Host "Checking if Resource Group $($rgName) exists"
    $rg = Get-AzureRmResourceGroup -Name $rgName -ErrorAction SilentlyContinue
    if($rg) {
        Write-Host "Resource group $($rgName) already exists, no need to create."
    } else {
        Write-Host "Creating resource group $($rgName)"
        $rg = New-AzureRmResourceGroup -Name $rgName -Location $location -ErrorAction Stop
    }
    Write-Verbose $jsonTemplateFileName
    Write-Verbose $jsonParameterFullFileName

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
# Macro replacement
###############################################################################

function New-Macro {
    Param (
        [parameter(mandatory=$true)]$Unparsed
    )
    $macro = New-Object PSObject
    $macro | Add-Member -Type NoteProperty -Name Parsed -Value $null
    $macro | Add-Member -Type NoteProperty -Name Unparsed -Value $Unparsed
    $macro | Add-Member -Type NoteProperty -Name SemiParsed -Value $null
    return $macro
}

function GetSubscriptionId {
    $context = Get-AzureRmContext
    return $context.Subscription.Id
}

function GetTenantId {
    $context = Get-AzureRmContext
    return $context.Tenant.Id
}

function ParseGlobalMacro {
    Param (
        [parameter(mandatory=$true)] [ref]$macro
    )
        
    # Prepare global macros (RegEx search strings)
    $globalMacros = @("\[tenantid\]", "\[subscriptionid\]")
    $iWorkString = if($macro.Value.SemiParsed) {$macro.Value.SemiParsed} else {$macro.Value.Unparsed}
    
    for ($i=0; $i -lt $globalMacros.Count; $i++) {
        # Find global macro in string
        $matches = [System.Text.RegularExpressions.Regex]::Matches($iWorkString, $globalMacros[$i], 1)
        $matches | ForEach-Object {
                
            $replacementString = ""

            switch ($globalMacros[$i]) {
                $globalMacros[0] { 
                    $replacementString = GetTenantId
                }
                $globalMacros[1] {
                    $replacementString = GetSubscriptionId
                }
            }

            $beginning = ($iWorkString.Substring(0, $_.Index))
            $end = ($iWorkString.Substring($_.Index + $_.Length, $iWorkString.Length - ($_.Index + $_.Length)))
            # Remove surrounding '#' if applicable
            if( $beginning.EndsWith("#") -and $end.StartsWith("#") ) {
                $beginning = $beginning.Substring($beginning.Length - 1, $beginning.Length - 1)
                $end = $end.Substring(1, $end.Length - 1)
            }
            $iWorkString = -join ($beginning, $replacementString, $end)
        }
    }
    $macro.Value.Parsed = $iWorkString
    $macro.Value.SemiParsed = $iWorkString
}

Function GetKeyVaultSecret {
    Param (
        $resourceMacro
    )
 
    $resourceIdPattern = "(?<=#)[\w\s/\-.]+(?=#secrets#)" 
    $resourceIdMatch = [System.Text.RegularExpressions.Regex]::Match($resourceMacro, $resourceIdPattern, 1)
    
    $secretNamePattern = "(?<=#secrets#)[\w\s/\-]+(?=.)"
    $secretNameMatch = [System.Text.RegularExpressions.Regex]::Match($resourceMacro, $secretNamePattern, 1)
    
    $secretReturnTypePattern = "(?<=#secrets#[\w\s/\-]+.)[\w\s/-]+(?=#)"
    $secretReturnType = [System.Text.RegularExpressions.Regex]::Match($resourceMacro, $secretReturnTypePattern, 1)
    
    switch($secretReturnType.Value.ToLower())
    {
        "secretvaluetext" {(Get-AzureKeyVaultSecret -ResourceId ($resourceIdMatch.Value) -Name ($secretNameMatch)).SecretValueText}
        "secretvalue" {(Get-AzureKeyVaultSecret -ResourceId ($resourceIdMatch.Value) -Name ($secretNameMatch)).SecretValue}
    }

}

function ParseResourceMacro {
    Param (
        [parameter(mandatory=$true)] [ref]$macro
    )

    #Only support microsoft.keyvault/secrets

    $ResourceProviders = @("providers/microsoft.keyvault")

    $stringToParse = if($macro.Value.SemiParsed) {$macro.Value.SemiParsed} else {$macro.Value.Unparsed}

    for ($i=0; $i -lt $ResourceProviders.Count; $i++) {
        
        # Find global macro in string
        $match = [System.Text.RegularExpressions.Regex]::Match($stringToParse, $ResourceProviders[$i], 1)
        if ($match.Success -eq $true)
        {
            $returnValue = ""
            switch ($i) {
                0 { 
                    $returnValue = GetKeyVaultSecret $stringToParse
                }
            }
            $macro.Value.Parsed = $returnValue
            break
        }
    }

}

function ParseMacro {
    Param (
        [parameter(mandatory=$true)] [ref]$macro
    )
    ParseGlobalMacro ([ref]($macro.Value))
    #$macro.Value | Format-List * #debug
    ParseResourceMacro ([ref]$macro.Value)
    #$macro.Value | Format-List * #debug
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
# Find all parameter files for the current dtap
###############################################################################
$templateParameters = Get-ChildItem -Path $sourcePath -Include azuredeploy.*parameters.json -Recurse

Write-Verbose ""
Write-Verbose "Searching for template parameters files."
Write-Verbose "$($templateParameters.Count) parameter file(s) found"
Write-Verbose "Listing files:"

# Loop through the configs and add the right files to the list, i.e. filter on dtap setting.
# This also filters the list in deployment order.
$unsortedList = @()
$logMsg = "";
Foreach ($file in $templateParameters) {
    $params = ((Get-Content -Raw $file) | ConvertFrom-Json)
    $logMsg = "$($params.parameters.dtap.value) - $($file.FullName)"
    if( $params.parameters.dtap.value -eq $dtap ) {
        Write-Verbose "To deploy: $logMsg"
        $templateParameters = New-Object -TypeName System.Object
        $templateParameters | Add-Member -MemberType NoteProperty -Name Path -Value $file.FullName
        $templateParameters | Add-Member -MemberType NoteProperty -Name Ring -Value $params.parameters.ring.value
        $unsortedList += $templateParameters
    } else {
        Write-Verbose "Not to deploy: $logMsg"        
    }
}

###############################################################################
# Find all powershell scripts for the current dtap
###############################################################################
$scriptFiles = Get-ChildItem -Path $sourcePath -Include pipeline-*.ps1 -Recurse

Write-Verbose ""
Write-Verbose "Searching for scripts."
Write-Verbose "$($scriptFiles.Count) scripts found"
Write-Verbose "Listing scripts:"

# Loop through the configs and add the right files to the list, i.e. filter on dtap setting.
# This also filters the list in deployment order.
$logMsg = "";
Foreach ($file in $scriptFiles) {
    # Parse out the ordinal number (execution order)
    $orderNoPattern = "(?<=pipeline-)[0-9]{3,3}(?=[\w\s-_.]*.ps1$)"
    $orderNo = [System.Text.RegularExpressions.Regex]::Match($file.FullName, $orderNoPattern).Value
    $logMsg = "$($orderNo) - $file"
    Write-Verbose "Script: $logMsg"

    $item = New-Object -TypeName System.Object
    $item | Add-Member -MemberType NoteProperty -Name Path -Value $file.FullName
    $item | Add-Member -MemberType NoteProperty -Name Ring -Value $orderNo
    $unsortedList += $item
}

$sortedRunlist = $unsortedList | Sort-Object -Property Ring

###############################################################################
# Loop through the list and deploy
###############################################################################

Write-Verbose ""
Write-Host "Run list:"
Foreach ($item in $sortedRunlist) {
    Write-Host $item.Path
}
Write-Verbose "Loop through each file and deploy"

$jsonParamFileRegexPattern = "azuredeploy[\w\s-.]*.parameters.json$"
#$lastDirRegexPattern = "[\w\s-.]+(?=\\azuredeploy[\w\s-.]*.parameters.json$)"
$rgNamePattern = "(?<=resource-groups\\)[\w\s-.]+"
$pathNoFilenameRegexPattern = "[\w\s-.\\:]+(?=azuredeploy[\w\s-.]*.parameters.json$)"

Foreach ($item in $sortedRunlist) {
    Write-Host "Processing: $($item.Path)"
    if ( $item.Path.Endswith(".json") -eq $true ) {
        ###############################################################################
        # Deploy a template
        ###############################################################################
        deployTemplate -fullPath $item.Path -SourceVersion $SourceVersion    
    } elseif ( $item.Path.Endswith(".ps1") -eq $true ) {
        ###############################################################################
        # Execute a script
        ###############################################################################
        Write-Verbose "##########################################################################################"
        Write-Verbose "Execution of $($item.Path)"
        & $item.Path -dtap $dtap -sourcePath $sourcePath -WhatIf $WhatIf
        if ($LastExitCode -eq 1) {
            Write-Error "Nested script failed. Terminating."
            exit 1
        }
        
    } else {
        $errorMessage = "Not recognizable file format: $($item.Path). Item will not be deployed."
        ("##vso[task.setvariable variable=WarningMessage] {0}" -f ($errorMessage) )
        Write-Warning "$($errorMessage)"
    }
}

