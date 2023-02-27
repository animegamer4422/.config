# Alias 
Set-Alias vim nvim
Set-Alias ll ls
Set-Alias grep findstr
Set-Alias -Name c -Value z -Option AllScope
Set-Alias edit helix
$psconfig = "$env:USERPROFILE/.config/powershell/user-profile.ps1"

# Function
function rm([string]$FileName)
{
	rm -recurse -force "$FileName"
}

function commit($message) {
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = Read-Host "Enter commit message"
    }

    Write-Host "Commit message is $message"
    git add .
    git commit -m "$message"
}


function install($name) {
    if (-not $name) {
        $name = Read-Host "App to Install"
    }
    $app = winget search -s=winget "$name" | Select-Object -Skip 3 | ForEach-Object { ($_ -split '\s{2,}')[0] } | Out-String | fzf
    $selected = winget search -s=winget "$app" | awk '/\S+\.\S+/ {print $2}'
    Write-Host "$selected"
    winget install --accept-package-agreements -h -s=winget "$selected"
}

# Set the prompt to Starship
Invoke-Expression (&starship init powershell)

# Import Modules

Import-Module Terminal-Icons
Import-Module PSFzf
Import-Module PSReadLine

# PSReadline 
Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineOption -EditMode Emacs
Set-PSReadLineOption -BellStyle None
Set-PSReadLineKeyHandler -Chord 'ctrl+d' -Function DeleteChar

#PSFzf 
Set-PsFzfOption -PSReadlineChordProvider 'ctrl+f' -PSReadlineChordReverseHistory 'ctrl+r'
