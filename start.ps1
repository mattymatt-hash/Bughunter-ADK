Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Starting BugHunter ADK" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

& ".\.venv\Scripts\Activate.ps1"

python main.py scan openai.com