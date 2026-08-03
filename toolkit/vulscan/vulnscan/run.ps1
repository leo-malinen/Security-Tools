$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot
python -m vulnscan @args
