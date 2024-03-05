function Install-Winget {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Output "winget is already installed."
    }
    else {
        write-output "Winget not Found"
        Write-Output "Installing winget..."
        irm -o "winget-install.ps1" "https://raw.githubusercontent.com/asheroto/winget-installer/master/winget-install.ps1" ; ./winget-install.ps1
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Output "winget has been installed."
        }
        else {
            Write-Output "winget installation failed."
        }
    }
}

Install-Winget

$installedPackages = winget show --installed
$packagesToCheck = @("Mozilla.Firefox", "DuongDieuPhap.ImageGlass", "Microsoft.PowerShell", "Microsoft.WindowsTerminal")
foreach ($package in $packagesToCheck) {
    if ($installedPackages -notcontains $package) {
        winget install -h $package -s=winget
    }
}


# Create a restore point
if((Get-ComputerRestorePoint).configured -eq $false) { Enable-ComputerRestore -Drive "$env:SystemDrive"}
Checkpoint-Computer -Description "System Restore Point before running auto-setup"

function scoop-invoke {
# Scoop
# Check if scoop is installed or not and install it if it isn't accordingly to the currently running session
if (!(Test-Path -Path "$env:USERPROFILE\scoop")) {
    # Check if the current session is running as an administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Download the Scoop installation script
irm -o scoop.ps1 'https://get.scoop.sh'

# Check if the current session is running as an administrator
if($isAdmin) {
    # Run Scoop installer with -RunAsAdmin
    pwsh -command "& {./scoop.ps1 -RunAsAdmin}"
} else {
    pwsh -command "& {./scoop.ps1}"
    }


pwsh /c scoop install aria2 git # use this to add 7-zip to context menu C:\Users\Hari\scoop\apps\7zip\current\install-context.reg
pwsh /c scoop config aria2-warning-enabled false
pwsh /c scoop update

# Scoop check buckets and add them accordingly
pwsh -command "& { $currentBuckets = scoop bucket list; return $currentBuckets }" | Set-Variable -Name currentBuckets
$bucketsToAdd = @("versions", "extras", "nerd-fonts")
foreach ($bucket in $bucketsToAdd) {
    if ($currentBuckets -notcontains $bucket) {
        pwsh -command "& { scoop bucket add $bucket }"
    }
}
pwsh -command "& { scoop install cacert dark ffmpeg fzf Hack-NF mpv neovim starship sudo wget yt-dlp }"

}
}

scoop-invoke

# Set UAC to Never Notify
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -PropertyType "DWord" -Force | Out-Null

# Powershell Config
$config = {
    $profilePath = $PROFILE.CurrentUserAllHosts
    if (!(Test-Path $profilePath)) {
        New-Item -ItemType File -Path $profilePath -Force
    }
    Add-Content -Path $profilePath -Value '. $env:USERPROFILE/.config/powershell/user-profile.ps1'
}
pwsh -Command $config
Add-Content -Path $profilePath -Value '. $env:USERPROFILE/.config/powershell/user-profile.ps1'
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
install-module -Force PSReadLine
install-module -Force PSFzf
install-module -Force Terminal-Icons

# MPV Config
$path = "$env:userprofile\scoop\persist\mpv\portable_config"
if (Test-Path $path) {Remove-Item -Recurse -Force $path}
New-Item -ItemType SymbolicLink -Path $path -Target "$env:userprofile\.config\mpv\portable_config"
