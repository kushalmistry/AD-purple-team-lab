<#
.SYNOPSIS
  Exports recent Windows events as flattened JSON Lines for replay in tests.

.DESCRIPTION
  Each event becomes one JSON object: Channel, EventID, Computer, TimeCreated, plus
  every named EventData field (TicketEncryptionType, LogonType, ImagePath, ...).
  Copy the output to your workstation, review it, and move the relevant events into
  tests/fixtures/<rule_name>/positive.jsonl or negative.jsonl.

.EXAMPLE
  .\Export-LabEvents.ps1 -Since (Get-Date).AddMinutes(-30) -EventId 4769,4768 -OutFile .\kerb.jsonl
#>
[CmdletBinding()]
param(
    [string[]]$LogName = @('Security', 'System', 'Microsoft-Windows-Sysmon/Operational'),
    [datetime]$Since = (Get-Date).AddHours(-2),
    [int[]]$EventId,
    [string]$OutFile = ".\events.jsonl"
)

$lines = foreach ($log in $LogName) {
    $filter = @{ LogName = $log; StartTime = $Since }
    if ($EventId) { $filter['Id'] = $EventId }

    Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $record = [ordered]@{
            Channel     = $_.LogName
            EventID     = $_.Id
            Computer    = $_.MachineName
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        }
        foreach ($field in $xml.Event.EventData.Data) {
            if ($field.Name) { $record[$field.Name] = $field.'#text' }
        }
        $record | ConvertTo-Json -Compress
    }
}

$lines | Set-Content -Path $OutFile -Encoding utf8
Write-Host "Wrote $(@($lines).Count) events to $OutFile"
