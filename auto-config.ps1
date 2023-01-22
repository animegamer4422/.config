
Start-Process powershell -Verb runAs -ArgumentList "-Command `"{
if((Get-ComputerRestorePoint).configured -eq $false) { Enable-ComputerRestore }
Checkpoint-Computer -Description "System Restore Point before running auto-setup"
}`"" -NoNewWindow

# Create a restore point
#
# Scoop
# Check if scoop is installed or not and install it if it isn't accordingly to the currently running session
if (!(Test-Path -Path "$env:USERPROFILE\scoop")) {
    # Check if the current session is running as an administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Download the Scoop installation script
$scoopScript = (new-object net.webclient).downloadstring('https://get.scoop.sh')
$scoopScript = $scoopScript | Out-String -Width 4096

# Check if the current session is running as an administrator
if($isAdmin) {
    # Run Scoop installer with -RunAsAdmin
    powershell -command "& {$scoopScript -RunAsAdmin}"
} else {
    powershell -command "& {$scoopScript}"
    }
}

scoop install aria2 git
scoop config aria2-warning-enabled false
scoop update

# Scoop check buckets and add them accordingly
$currentBuckets = scoop bucket list
$bucketsToAdd = @("main", "versions", "extras", "nerd-fonts")
foreach ($bucket in $bucketsToAdd) {
    # Check if the current bucket is already installed
    if ($currentBuckets -notcontains $bucket) {
        # Add the bucket if it's not already installed
        scoop bucket add $bucket
    }
}

scoop install cacert dark ffmpeg fzf Hack-NF mpv neovim starship sudo wget yt-dlp

# Winget

# Check if winget is installed
if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
    # Set the PowerShell Gallery repository to Trusted
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

    # Install winget without prompting for confirmation
    Install-Script -Name winget-install -Force
    write-host 'Installing Winget'
    winget-install
}

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

# Remove EDGE completely from the system

sudo cmd ./edge-Uninstall.bat

#Set the updates to Security Only
write-host "`n Setting updates to Security Only"


Write-Host "Disabling driver offering through Windows Update..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
Write-Host "Disabling Windows Update automatic restart..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
}
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
        Write-Host "Disabled driver offering through Windows Update"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays " -Type DWord -Value 4
    
        $ButtonType = [System.Windows.MessageBoxButton]::OK
        $MessageboxTitle = "Set Security Updates"
        $Messageboxbody = ("Recommended Update settings loaded")
        $MessageIcon = [System.Windows.MessageBoxImage]::Information

        [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
        Write-Host "Updates Set to Recommended"
