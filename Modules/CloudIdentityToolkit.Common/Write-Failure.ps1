Function Write-Failure
{
    param([string]$Message)
    Write-Host "  ✖ " -NoNewline -ForegroundColor Red
    Write-Host $Message -ForegroundColor White
}
