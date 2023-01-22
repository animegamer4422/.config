$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (!$isAdmin) {
    Write-Host "The current session is not running as an administrator. Opening a new elevated PowerShell window..."
    Start-Process powershell -Verb runAs -ArgumentList "-Command `"& {& '$MyInvocation.MyCommand.Path'}`"" -NoNewWindow
    exit
}

$currentPSVersion = $PSVersionTable.PSVersion.Major
Write-Host "The current PowerShell version is $currentPSVersion"

$latestReleasePage = (New-Object Net.WebClient).DownloadString("https://github.com/PowerShell/PowerShell/releases/latest")
$latestPSVersion = ($latestReleasePage | Select-String -Pattern "PowerShell ([0-9]+\.[0-9]+\.[0-9]+)" -AllMatches).Matches.Groups[1].Value
$latestPSVersion = [version]$latestPSVersion

if ($currentPSVersion -lt $latestPSVersion.Major) {
    if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
        # Set the PowerShell Gallery repository to Trusted
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        # Install winget without prompting for confirmation
        Install-Script -Name winget-install -Force
        winget-install
    }
    Write-Host "Updating PowerShell to version $latestPSVersion"
    winget install Microsoft.PowerShell
} else {
    Write-Host "PowerShell is already up to date"
    if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
        # Set the PowerShell Gallery repository to Trusted
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        # Install winget without prompting for confirmation
        Install-Script -Name winget-install -Force
        winget-install
    }
}

$scriptPath = "$pwd
