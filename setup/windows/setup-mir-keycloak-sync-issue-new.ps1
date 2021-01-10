Write-Host "Setup MIR - Create idbroker-updater.jks"

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$result=(Invoke-RestMethod -Uri http://localhost:8080/auth/realms/MCP/protocol/openid-connect/token -Body "grant_type=password&client_id=setupclient&username=mcp-admin@maritimeconnectivity.net&password=admin" -Method Post)
Write-Host "--"
Write-Host "-- Token request response: $result"
Write-Host "--"

$token=$result -replace '@{access_token=([^;]+);.*', '$1'
Write-Host "--"
Write-Host "-- Token: $token"
Write-Host "--"

$cert=(Invoke-RestMethod -Uri http://localhost:8444/oidc/api/org/urn:mrn:mcp:org:idp1:dma/device/urn:mrn:mcp:device:idp1:dma:sync/certificate/issue-new -Headers @{"Authorization" = "Bearer $token"} -Method Get)
Write-Host "--"
Write-Host "-- Cert: $cert"
Write-Host "--"

$base64Keystore=$cert -replace '.*jksKeystore=([^ ]*); .*', '$1'
Write-Host "--"
Write-Host "-- BASE64 Keystore: '$base64Keystore'"
Write-Host "--"

$pwd=$cert -replace '.*keystorePassword=([^ ]*);?.*}', '$1'
Write-Host "--"
Write-Host "-- BASE64 Keystore password: '$pwd'"
Write-Host "--"

$filename="idbroker-updater.jks"
$base64KeystoreBytes = [Convert]::FromBase64String($base64Keystore)
[IO.File]::WriteAllBytes($filename, $base64KeystoreBytes)
Write-Host "--"
Write-Host "-- Saved the keystore to file : $filename"
Write-Host "--"

$pwdFilename="idbroker-updater-password.txt"
$pwdBytes = [System.Text.Encoding]::UTF8.GetBytes($pwd)
[IO.File]::WriteAllBytes($pwdFilename, $pwdBytes)
Write-Host "--"
Write-Host "-- Saved the keystore password to file : $pwdFilename"
Write-Host "--"

Read-Host
