param([string] $AndroidNdk = $env:ANDROID_NDK_HOME)
$ErrorActionPreference = 'Stop'
if (-not $AndroidNdk) { throw 'Set ANDROID_NDK_HOME or pass -AndroidNdk (tested with NDK r27d).' }
$repoRoot = Split-Path $PSScriptRoot -Parent
$appDirectory = Join-Path $repoRoot 'netguard/app'
$sourceDirectory = Join-Path $appDirectory 'src/main/jni/netguard'
$compiler = Join-Path $AndroidNdk 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'This script requires the Windows Android NDK. See CMakeLists.txt for other hosts.' }
$files = @('netguard.c','session.c','ip.c','tcp.c','udp.c','icmp.c','tls.c','dns.c','dhcp.c','pcap.c','util.c') | ForEach-Object { Join-Path $sourceDirectory $_ }
foreach ($target in @(@('arm64-v8a','aarch64-linux-android29'),@('x86_64','x86_64-linux-android29'))) {
    $outputDirectory = Join-Path $appDirectory ('src/main/jniLibs/' + $target[0])
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    & $compiler ('--target=' + $target[1]) -shared -fPIC -O2 -g0 '-Wl,-z,max-page-size=16384' '-Wl,--strip-all' ('-ffile-prefix-map=' + $sourceDirectory + '=netguard') ('-I' + $sourceDirectory) @files -llog -o (Join-Path $outputDirectory 'libnetguard.so')
    if ($LASTEXITCODE -ne 0) { throw ('NetGuard JNI build failed: ' + $target[0]) }
}
