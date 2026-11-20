param([switch]$Live,[switch]$InjectFailure)
$ErrorActionPreference='Stop'
$entry=Join-Path $PSScriptRoot 'run-lab.py'
$argsList=@($entry)
if($Live){$argsList+='--live'}
if($InjectFailure){$argsList+='--inject-failure'}
python @argsList
exit $LASTEXITCODE
