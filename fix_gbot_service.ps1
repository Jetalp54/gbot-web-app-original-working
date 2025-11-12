# GBot Service Diagnostic and Fix Script for Windows/Linux

Write-Host "=== GBot Service Diagnostic and Fix Script ===" -ForegroundColor Green

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run as Administrator" -ForegroundColor Red
    exit 1
}

Write-Host "1. Checking if this is a Linux environment..." -ForegroundColor Yellow
if (Get-Command "systemctl" -ErrorAction SilentlyContinue) {
    Write-Host "✅ Linux environment detected" -ForegroundColor Green
    
    Write-Host "2. Checking service status..." -ForegroundColor Yellow
    systemctl status gbot.service
    
    Write-Host "3. Checking service logs..." -ForegroundColor Yellow
    journalctl -u gbot.service --no-pager -n 50
    
    Write-Host "4. Checking application directory..." -ForegroundColor Yellow
    if (Test-Path "/opt/gbot-web-app") {
        Write-Host "✅ Directory exists: /opt/gbot-web-app" -ForegroundColor Green
        Get-ChildItem "/opt/gbot-web-app" -Force
    } else {
        Write-Host "❌ Directory not found: /opt/gbot-web-app" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "5. Checking virtual environment..." -ForegroundColor Yellow
    if (Test-Path "/opt/gbot-web-app/venv") {
        Write-Host "✅ Virtual environment exists" -ForegroundColor Green
        Get-ChildItem "/opt/gbot-web-app/venv/bin" -Force
    } else {
        Write-Host "❌ Virtual environment not found" -ForegroundColor Red
        Write-Host "Creating virtual environment..." -ForegroundColor Yellow
        Set-Location "/opt/gbot-web-app"
        python3 -m venv venv
        & "/opt/gbot-web-app/venv/bin/activate"
        pip install -r requirements.txt
    }
    
    Write-Host "6. Testing application..." -ForegroundColor Yellow
    Set-Location "/opt/gbot-web-app"
    & "/opt/gbot-web-app/venv/bin/python" -c "import app; print('✅ App imports successfully')"
    
    Write-Host "7. Restarting service..." -ForegroundColor Yellow
    systemctl daemon-reload
    systemctl stop gbot.service
    systemctl start gbot.service
    systemctl status gbot.service
    
} else {
    Write-Host "❌ This appears to be a Windows environment" -ForegroundColor Red
    Write-Host "The service error suggests you're running on Linux." -ForegroundColor Yellow
    Write-Host "Please run this script on your Linux server where the service is installed." -ForegroundColor Yellow
}

Write-Host "=== Diagnostic Complete ===" -ForegroundColor Green
