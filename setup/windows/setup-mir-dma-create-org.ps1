Write-Host "Setup MIR - Create DMA organization"

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$result=(Invoke-RestMethod -Uri http://localhost:8080/auth/realms/MCP/protocol/openid-connect/token -Body "grant_type=password&client_id=setupclient&username=mcp-admin@maritimeconnectivity.net&password=admin" -Method Post)
Write-Host "--"
Write-Host "-- Token request response: $result"
Write-Host "--"

$token=$result -replace '@{access_token=([^;]+);.*', '$1'
Write-Host "--"
Write-Host "-- Token: $token"
Write-Host "--"

$response=Invoke-RestMethod -Uri http://localhost:8444/oidc/api/org/apply -ContentType "application/json" -InFile "..\dma.json" -Method Post
Write-Host "--"
Write-Host "-- Response: $response"
Write-Host "--"

Read-Host