$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$env:PATH='E:\Anaconda3\Library\bin;'+$env:PATH
$env:QT_QPA_PLATFORM_PLUGIN_PATH='E:\Anaconda3\Library\plugins\platforms'
$env:QT_QPA_PLATFORM='windows'
& (Join-Path $root 'build\Release\lab1_sniffer.exe') @args
exit $LASTEXITCODE
