# Alias 
Set-Alias vim nvim
Set-Alias gawk awk
Set-Alias ll ls
Set-Alias grep findstr
Set-Alias -Name c -Value z -Option AllScope

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
