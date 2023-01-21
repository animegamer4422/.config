# Scoop

scoop install aria2 git
scoop config aria2-warning-enabled false
scoop update

# Scoop check buckets and add them accordingly

# Get the list of currently installed buckets
$currentBuckets = scoop bucket list

# Define the list of buckets to be added
$bucketsToAdd = @("main", "versions", "extras", "nerd-fonts")

# Loop through the list of buckets to be added
foreach ($bucket in $bucketsToAdd) {
    # Check if the current bucket is already installed
    if ($currentBuckets -notcontains $bucket) {
        # Add the bucket if it's not already installed
        scoop bucket add $bucket
    }
}

scoop install cacert dark ffmpeg fzf gawk Hack-NF mpv neovim starship sudo wget yt-dlp

# Winget

winget upgrade
winget upgrade --all -h
$installedPackages = winget show --installed

$packagesToCheck = @("Microsoft.DesktopAppInstaller_8wekyb3d8bbwe", "Microsoft.VCRedist.2015+.x64", "Microsoft.VCRedist.2015+.x86", "DuongDieuPhap.ImageGlass", "Microsoft.Powershell", "Microsoft.DotNet.DesktopRuntime.6", "Eugeny.Tabby", "Mozilla.Firefox")

foreach ($package in $packagesToCheck) {
    if ($installedPackages -notcontains $package) {
        winget install $package
    }
}


# Set UAC to Never Notify

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -PropertyType "DWord" -Force | Out-Null

# Tabby Config
$username = $env:username
if (Test-Path "C:\Users\$username\AppData\Roaming\tabby\config.yaml") { Remove-Item "C:\Users\$username\AppData\Roaming\tabby\config.yaml"}
Copy-Item "./tabby/config.yaml" "C:\Users\$username\AppData\Roaming\tabby\config.yaml"

# MPV Config
$path = "$env:userprofile\scoop\persist\mpv\portable_config"
if (Test-Path $path) {Remove-Item -Recurse -Force $path}
New-Item -ItemType SymbolicLink -Path $path -Target "$env:userprofile\.config\mpv\portable_config"

# TWEAKS

# Create a restore point
Checkpoint-Computer -Description "System Restore Point before running auto-setup"

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
