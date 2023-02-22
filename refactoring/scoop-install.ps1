$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
write-host "Downloading Scoop installer"
curl -o "install.ps1" "https://raw.githubusercontent.com/scoopinstaller/install/master/install.ps1"

$scriptBlock = {
    param($RunAsAdmin)
    if($RunAsAdmin){
        .\install.ps1 -RunAsAdmin
    } else {
        .\install.ps1
    }
}

if($isAdmin) {
    &$scriptBlock -RunAsAdmin
} else {
    &$scriptBlock
}
