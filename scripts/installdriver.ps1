$name = "VulnerableDriver"
$sharedPath = "Z:\VulnerableDriver.sys"
$path = "C:\Users\WDKRemoteUser\Downloads\VulnerableDriver.sys"

sc.exe stop $name
sc.exe delete $name

Write-Host "Copying driver to $path"
copy $sharedPath $path

sc.exe create $name type= kernel start= demand binPath= $path
sc.exe start $name