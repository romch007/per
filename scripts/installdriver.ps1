$name = "VulnerableDriver"
$path = "C:\Users\WDKRemoteUser\Downloads\VulnerableDriver.sys"

sc.exe stop $name
sc.exe delete $name

sc.exe create $name type= kernel start= demand binPath= $path
sc.exe start $name