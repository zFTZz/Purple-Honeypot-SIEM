# Fallback opcional: alerta no Microsoft Teams via Incoming Webhook.
# O caminho principal do projeto é o Telegram (webhook_dispatcher.py).
#
# Uso no PowerShell:
#   $env:TEAMS_WEBHOOK_URL = "https://...webhook.office.com/..."
#   .\alerting\teams_alert.ps1 -Title "Teste SOC" -Text "Alerta de laboratório"
#
param(
    [string]$WebhookUrl = $env:TEAMS_WEBHOOK_URL,
    [string]$Title = "Alerta SOC - Purple Honeypot SIEM",
    [string]$Text = "Teste de integração do Purple Honeypot SIEM."
)

if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
    Write-Error "Defina TEAMS_WEBHOOK_URL ou passe -WebhookUrl."
    exit 1
}

$body = @{
    "@type"    = "MessageCard"
    "@context" = "http://schema.org/extensions"
    themeColor = "D13438"
    summary    = $Title
    sections   = @(
        @{
            activityTitle = $Title
            activityText  = $Text
            markdown      = $true
        }
    )
} | ConvertTo-Json -Depth 6

try {
    Invoke-RestMethod -Method Post -Uri $WebhookUrl -ContentType "application/json" -Body $body | Out-Null
    Write-Host "[+] Alerta enviado ao Teams."
} catch {
    Write-Error "Falha ao enviar ao Teams: $($_.Exception.Message)"
    exit 1
}
