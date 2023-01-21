# Scoop

#irm get.scoop.sh | iex
scoop install aria2 git
scoop config aria2-warning-enabled false
scoop update
scoop bucket add main
scoop bucket add extras
scoop bucket add versions
scoop bucket add nerd-fonts
scoop install cacert dark ffmpeg fzf gawk Hack-NF mpv neovim starship sudo wget yt-dlp

# Winget

winget upgrade
winget upgrade --all -h
winget install -h Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
winget install -h Microsoft.VCRedist.2015+.x64
winget install -h Microsoft.VCRedist.2015+.x86
winget install -h DuongDieuPhap.ImageGlass
winget install -h Microsoft.Powershell
winget install -h Microsoft.DotNet.DesktopRuntime.6
winget install -h Eugeny.Tabby
winget install -h Mozilla.Firefox
winget install -h Nilesoft.shell

# Set UAC to Never Notify

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -PropertyType "DWord" -Force | Out-Null

# Tabby Config

rm C:\Users\Hari\AppData\Roaming\tabby\config.yaml
cp .\tabby\config.yaml C:\Users\Hari\AppData\Roaming\tabby\ 

# MPV Config

rm -recurse -force C:\Users\Hari\scoop\persist\mpv\portable_config
sudo cmd /c mklink /D C:\Users\Hari\scoop\persist\mpv\portable_config C:\Users\Hari\.config\mpv\portable_config

# TWEAKS


# Create a restore point
#Checkpoint-Computer -Description "System Restore Point before running auto-setup"

# Disable the built-in advertising ID
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord

# Disable the built-in telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord

# Disable the built-in app suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord

# Disable the built-in OneDrive
If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive") {
    Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Recurse
}
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -PropertyType DWord -Force | Out-Null

# Disable the built-in power throttling
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "CsEnabled" -Value 0 -Type DWord

# Change power plan to high performance
$Powercfg = powercfg.exe /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
Invoke-Expression $Powercfg

# Remove all the Start menu pinned applications

Get-ChildItem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" -Recurse -Include "*.lnk" | ForEach-Object {Remove-Item $_.FullName}

# Remove all the uwp apps
sudo pwsh /c import-module appx -usewindowspowershell; Get-AppxPackage -AllUsers | Where-Object {$_.Name -notlike "*store*"} | Remove-AppxPackage; exit 
