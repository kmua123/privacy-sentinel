param(
    [string] $AndroidSdk = $env:ANDROID_HOME,
    [string] $AndroidNdk = $env:ANDROID_NDK_HOME,
    [string] $JavaHome = $env:JAVA_HOME,
    [string] $GoHome = '',
    [string] $ToolsDirectory = (Join-Path $PSScriptRoot '.tools/bin')
)
$ErrorActionPreference = 'Stop'
if (!$AndroidSdk) { $AndroidSdk = $env:ANDROID_SDK_ROOT }
if (!$AndroidSdk -and $env:LOCALAPPDATA) {
    $AndroidSdk = Join-Path $env:LOCALAPPDATA 'Android/Sdk'
}
if (!$AndroidSdk -or !(Test-Path -LiteralPath (Join-Path $AndroidSdk 'platforms'))) {
    throw 'Set -AndroidSdk or ANDROID_HOME to an installed Android SDK.'
}
if (!$AndroidNdk -or !(Test-Path -LiteralPath (Join-Path $AndroidNdk 'source.properties'))) {
    throw 'Set -AndroidNdk or ANDROID_NDK_HOME to an installed Android NDK r27d (or newer) directory.'
}
if (!$JavaHome -or !(Test-Path -LiteralPath (Join-Path $JavaHome 'bin'))) {
    throw 'Set -JavaHome to a JDK 17 or newer directory.'
}
if ($GoHome) {
    $goBin = Join-Path (Resolve-Path -LiteralPath $GoHome).Path 'bin'
    $env:PATH = $goBin + [IO.Path]::PathSeparator + $env:PATH
}
if (!(Get-Command go -ErrorAction SilentlyContinue)) {
    throw 'Install Go 1.27.4 (or a compatible newer toolchain), add go to PATH, or set -GoHome.'
}
New-Item -ItemType Directory -Force -Path $ToolsDirectory | Out-Null
$env:ANDROID_HOME = (Resolve-Path -LiteralPath $AndroidSdk).Path
$env:ANDROID_NDK_HOME = (Resolve-Path -LiteralPath $AndroidNdk).Path
$env:JAVA_HOME = (Resolve-Path -LiteralPath $JavaHome).Path
$env:GOBIN = (Resolve-Path -LiteralPath $ToolsDirectory).Path
$env:GOTOOLCHAIN = 'local'
$env:PATH = $env:GOBIN + [IO.Path]::PathSeparator + (Join-Path $env:JAVA_HOME 'bin') + [IO.Path]::PathSeparator + $env:PATH
Push-Location $PSScriptRoot
try {
    & go test -trimpath '-tags=with_gvisor,cmfa,no_easytier,no_tailscale' .
    if ($LASTEXITCODE -ne 0) { throw 'Guard regression tests failed.' }
    $mobile = 'v0.0.0-20261011034528-197770444867'
    & go install -trimpath "golang.org/x/mobile/cmd/gomobile@$mobile"
    if ($LASTEXITCODE -ne 0) { throw 'gomobile build failed.' }
    & go install -trimpath "golang.org/x/mobile/cmd/gobind@$mobile"
    if ($LASTEXITCODE -ne 0) { throw 'gobind build failed.' }
    # Strip host checkout paths and align both shared libraries for 16 KB devices.
    # External linking is required for the NDK linker option to take effect.
    & gomobile bind -trimpath '-target=android/arm64,android/amd64' -androidapi=29 '-tags=with_gvisor,cmfa,no_easytier,no_tailscale' '-ldflags=-s -w -linkmode=external -extldflags=-Wl,-z,max-page-size=16384' -o guardcore.aar .
    if ($LASTEXITCODE -ne 0) { throw 'Android core build failed.' }
    Get-FileHash -LiteralPath './guardcore.aar' -Algorithm SHA256
} finally {
    Pop-Location
}
