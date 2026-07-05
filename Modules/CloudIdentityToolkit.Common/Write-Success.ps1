Function Write-Success
{
    param([string]$Message)
    Write-Host "  ✔ " -NoNewline -ForegroundColor Green
    Write-Host $Message -ForegroundColor White
}
