function Install-Winget {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Output "winget is already installed."
    }
    else {
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

