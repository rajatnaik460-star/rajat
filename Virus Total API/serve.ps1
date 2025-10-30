$ErrorActionPreference = "Stop"
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Path)

$port = 5500
$url = "http://localhost:$port"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "python"
$psi.ArgumentList = @("-m", "http.server", "$port", "-d", ".")
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($psi)
Start-Sleep -Milliseconds 700
Start-Process $url

Write-Host "Server started on $url (Ctrl+C in this window to stop if foreground)."

