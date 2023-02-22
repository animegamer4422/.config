Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Script winget-install
winget-install
winget install -h Microsoft.Powershell
