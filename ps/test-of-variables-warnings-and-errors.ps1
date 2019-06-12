$errorMessage = "Severe error happened"
"Just stdout:"
$errorMessage

""
"Setting the ErrorMessage variable:"
Write-Host "$("##vso[task.setvariable variable=ErrorMessage]") $($errorMessage)"

""
"Doing the task.LogIssue type=error. With ErrorMessage"
Write-Host "$("##vso[task.LogIssue type=error;]") $($env:ErrorMessage)"
"Environment variables are not set in the same script as DevOps needs to process the output first."

""
"Doing the task.LogIssue type=error. With custom message"
Write-Host "$("##vso[task.LogIssue type=error;]") Hey, something got wrong."

"This one does the trick and fails the build pipeline"
Write-Error "$($errorMessage)"




$errorMessage = "Severe error happened"
Write-Host "$("##vso[task.setvariable variable=ErrorMessage]") $($errorMessage)"
Write-Error "$($errorMessage)"