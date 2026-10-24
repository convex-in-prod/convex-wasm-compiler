[CmdletBinding()]
param(
    [string] $Distribution,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CompilerArguments
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$wslArguments = @()
if ($Distribution) { $wslArguments = @('--distribution', $Distribution) }
$metadata = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'toolchain-release.json') -Raw | ConvertFrom-Json
if ($metadata.kind -ne 'convex-wasm-wsl2-release-v1' -or
    $metadata.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $metadata.archive -cnotmatch '^convex-wasm-toolchain-[0-9.]+-linux-x64\.tar\.gz$') {
    throw 'Invalid WSL2 toolchain release metadata.'
}
$archive = Join-Path $PSScriptRoot $metadata.archive
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $metadata.sha256) {
    throw 'The bundled Linux archive differs from the release checksum.'
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'Install WSL2 and Ubuntu 24.04 first: wsl --install -d Ubuntu-24.04'
}
# Use --exec with separate arguments. Passing user arguments through sh -c would
# make quotes and shell syntax in paths or arguments executable shell input.
$installer = & wsl.exe @wslArguments --exec wslpath -a -u (Join-Path $PSScriptRoot 'install-wsl-toolchain.sh')
if ($LASTEXITCODE -ne 0) { throw 'Cannot access the selected WSL distribution. Install and start a WSL2 distribution first.' }
$linuxArchive = & wsl.exe @wslArguments --exec wslpath -a -u $archive
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the toolchain archive inside WSL.' }
if (-not $CompilerArguments -or $CompilerArguments.Count -eq 0) { $CompilerArguments = @('--help') }
& wsl.exe @wslArguments --exec /bin/sh $installer.Trim() $linuxArchive.Trim() $metadata.sha256 @CompilerArguments
exit $LASTEXITCODE
