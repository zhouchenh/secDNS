$ErrorActionPreference = 'Stop'
$fixtureRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$facadeRoot = (Resolve-Path (Join-Path $fixtureRoot '../era-facade-wt-app-hosts-20261022')).Path
if ((git -C $facadeRoot rev-parse HEAD) -ne '8da83c60274b66ae1b2da23bd9d731a88a5ab358') { throw 'Facade HEAD differs from reviewed fixture source' }
if (git -C $facadeRoot status --porcelain) { throw 'Facade source worktree is dirty' }
$helperOutput = Join-Path $env:TEMP ("secdns-facade-helper-" + [guid]::NewGuid().ToString() + ".exe")
go build -C $PSScriptRoot -o $helperOutput .
if ($LASTEXITCODE -ne 0) { throw 'helper build failed' }
$env:SECDNS_FACADE_HELPER = $helperOutput
go -C $fixtureRoot test ./internal/listeners/servers/http/admin/server -run '^TestFacadeRealTLS$' -v -count=1 -timeout 25m
if ($LASTEXITCODE -ne 0) { throw 'E2E failed' }

