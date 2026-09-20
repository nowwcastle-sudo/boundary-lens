#Requires -Version 7.0
[CmdletBinding()]
param()
# The retired name-based mocks are replaced by the native paths contract checks.
# Keep this entrypoint for existing CI/runbooks; run its distinct group once.
& (Join-Path $PSScriptRoot 'native-collector.ps1') -Group 'paths'
exit $LASTEXITCODE
