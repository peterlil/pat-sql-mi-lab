# This scripts adds administrator login credentials to the pat-core Azure Key Vault
param(
    $vaultName,
    $name,
    $secretValue
)

Set-AzureKeyVaultSecret -VaultName $vaultName -Name $name -SecretValue $secretValue
