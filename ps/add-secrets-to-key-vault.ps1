
$params = ((Get-Content -Raw .\resource-groups\sql-mi-lab\azuredeploy.core.parameters.json) | ConvertFrom-Json)
$VaultName = $params.parameters.'key-vault-name'.value
$context = Get-AzureRmContext
$context.Tenant.Id

.\ps\add-secret-to-key-vault.ps1 -vaultName $VaultName -name 'SqlMiAdmin' -secretValue "<todo/>"
