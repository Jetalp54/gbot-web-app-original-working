# Fix PostgreSQL sequence sync issue for whitelisted_ip table
# This script should be run on the production server

Write-Host "🔧 Fixing PostgreSQL sequence sync issue..." -ForegroundColor Yellow

# Check if we're on the production server
if (-not (Test-Path "/etc/nginx/sites-available/gbot")) {
    Write-Host "❌ This script should be run on the production server" -ForegroundColor Red
    exit 1
}

# Get the script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Check if .env file exists
if (-not (Test-Path ".env")) {
    Write-Host "❌ .env file not found" -ForegroundColor Red
    exit 1
}

# Load environment variables from .env file
Get-Content .env | ForEach-Object {
    if ($_ -match "^([^#][^=]+)=(.*)$") {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}

# Check if DATABASE_URL is set
$DatabaseUrl = $env:DATABASE_URL
if (-not $DatabaseUrl) {
    Write-Host "❌ DATABASE_URL not found in .env file" -ForegroundColor Red
    exit 1
}

Write-Host "📊 Database URL: $DatabaseUrl" -ForegroundColor Cyan

# Run the PostgreSQL fix script
Write-Host "🚀 Running PostgreSQL sequence fix..." -ForegroundColor Green
python3 fix_postgresql_sequence.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Database sequence fix completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🎉 You should now be able to:" -ForegroundColor Green
    Write-Host "  - Add new IP addresses" -ForegroundColor White
    Write-Host "  - Delete existing IP addresses" -ForegroundColor White
    Write-Host "  - Use emergency access without errors" -ForegroundColor White
} else {
    Write-Host "❌ Database sequence fix failed!" -ForegroundColor Red
    exit 1
}
