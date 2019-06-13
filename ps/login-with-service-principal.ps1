# Secret
$secpasswd = ConvertTo-SecureString '' -AsPlainText -Force; 

# Azure AD Application ID
$creds = New-Object System.Management.Automation.PSCredential ('', $secpasswd);

# Tenant ID
Login-AzureRmAccount -Credential $creds -ServicePrincipal -TenantId 