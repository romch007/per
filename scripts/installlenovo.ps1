$name = "LnvMSRIO"
$sharedPath = "Z:\LnvMSRIO.sys"
$path = "C:\Users\WDKRemoteUser\Downloads\LnvMSRIO.sys"

sc.exe stop $name
sc.exe delete $name

Write-Host "Copying driver to $path"
copy $sharedPath $path

sc.exe create $name type= kernel start= demand binPath= $path
sc.exe start $name