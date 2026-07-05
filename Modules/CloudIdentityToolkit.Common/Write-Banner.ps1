Function Write-Banner
{
    param (
        [string]$Title,
        [string]$Subtitle
    )

    Clear-Host

    $width = 66
    $line  = "╔" + ("═" * ($width-2)) + "╗"
    $bottom= "╚" + ("═" * ($width-2)) + "╝"

    $titleLine = "║" + $Title.PadLeft(($width-2 + $Title.Length)/2).PadRight($width-2) + "║"
    $subLine   = "║" + $Subtitle.PadLeft(($width-2 + $Subtitle.Length)/2).PadRight($width-2) + "║"

    Write-Host $line -ForegroundColor Cyan
    Write-Host $titleLine -ForegroundColor Cyan
    Write-Host $subLine -ForegroundColor Cyan
    Write-Host $bottom -ForegroundColor Cyan
    Write-Host ""
}
