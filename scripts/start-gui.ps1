$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if ($env:LAB1_QT_ROOT) {
    $env:PATH=(Join-Path $env:LAB1_QT_ROOT 'bin')+[IO.Path]::PathSeparator+$env:PATH
    $env:QT_QPA_PLATFORM_PLUGIN_PATH=Join-Path $env:LAB1_QT_ROOT 'plugins\platforms'
}
$build=if ($env:LAB1_BUILD_DIR) { $env:LAB1_BUILD_DIR } else { Join-Path $root 'build' }
& (Join-Path $build 'Release\lab1_sniffer.exe') @args
exit $LASTEXITCODE
