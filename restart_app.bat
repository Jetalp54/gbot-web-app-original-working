@echo off
echo Stopping any running python processes... (You might need to confirm or press Ctrl+C in the other window)
taskkill /IM python.exe /F 2>nul

echo.
echo Starting G-Bot Web App...
echo Migration will run automatically on startup.
echo.
python app.py
pause
