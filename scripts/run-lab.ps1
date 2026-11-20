param([switch]$Live,[switch]$InjectFailure,[switch]$InjectTimeout)
$ErrorActionPreference='Stop'
$entry=Join-Path $PSScriptRoot 'run-lab.py'
$argsList=@($entry)
if($Live){$argsList+='--live'}
if($InjectFailure){$argsList+='--inject-failure'}
if($InjectTimeout){$argsList+='--inject-timeout'}
python @argsList
exit $LASTEXITCODE
