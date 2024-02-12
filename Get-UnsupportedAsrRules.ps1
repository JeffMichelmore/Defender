function Get-UnsupportedAsrRule {
    param (
        [string]$senseLogPath
    )

    if (-not $senseLogPath){
        $senseLogPath = [System.Environment]::ExpandEnvironmentVariables("%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-SENSE%4Operational.evtx")
    }
   
    $senseLog = Get-WinEvent -Path $senseLogPath
    $affectedRules = @()
    foreach ($log in $senseLog){
        # check if $log.message contains an unsupported ASR rule
        $regexPattern = '[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}'
        if ($log.properties.value -like '*SENSECM: WRN: ASR: at least one requested rule is not supported by this platform*' -and $log.properties.value -match $regexPattern){
            $affectedRule = $matches[0]
            
            if ($affectedRules -notcontains $affectedRule) {
                $affectedRules += $affectedRule
            }
        }
    }
    if ($affectedRules.Count -gt 0) {
        Write-Host "Unsupported ASR rules found:"
        foreach ($rule in $affectedRules) {
            Write-Host $rule
        }
        Write-Host "`nASR Rule Name to GUID Matrix:"
        Write-Host "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix"
    } else {
        Write-Host "No unsupported ASR rules found."
    }
}
Get-UnsupportedAsrRule
