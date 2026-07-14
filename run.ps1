<#
Helper PowerShell script to create/activate a virtual environment, install deps,
initialize the DB if missing, and run the dev server (Windows PowerShell).
#>
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
Push-Location $RepoRoot
try {
    if (-Not (Test-Path -Path .venv)) {
        python -m venv .venv
    }

    # Activate the virtualenv
    . .\.venv\Scripts\Activate.ps1

    # Install requirements
    pip install -r requirements.txt

    # Initialize DB if missing
    if (-Not (Test-Path -Path intracomms.db)) {
        python -m flask --app server/server.py init-db
    }

    # Set debug and run the server
    $env:FLASK_DEBUG = '1'
    python server/server.py
}
finally {
    Pop-Location
}
