function Get-UnsupportedASRs {
    param (
        [string]$senseLogPath
    )

    if (-not $senseLogPath){
        $senseLogPath = [System.Environment]::ExpandEnvironmentVariables("%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-SENSE%4Operational.evtx")
    }
   
    $senseLog = Get-WinEvent -Path $senseLogPath
    foreach ($log in $senseLog){
        # check if $log contains an unsupported ASR rule
        $regexPattern = '(?i)[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}'
        if ($log.properties.value -like '*SENSECM: WRN: ASR:VerAssign returns false*' -and $log.properties.value -match $regexPattern){

            Write-Host "ASR policy failure event found:`r`n" -ForegroundColor Red
            Write-Host $log.TimeCreated -ForegroundColor Green
            Write-Host $log.Properties.value
            Write-Host "`r`nRefer to below documentation for supported ASR rule matrix:"
            Write-Host "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix" -ForegroundColor Cyan
            Break
        }
        else {
            Write-Host "No ASR policy failures found." -ForegroundColor Green
        }

    }
}

Get-UnsupportedASRs
