Function Write-Info
{
    param([string]$Message)
    Write-Host "  ℹ " -NoNewline -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Gray
}
