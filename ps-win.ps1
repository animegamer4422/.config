$PSVersionTable = Get-Item "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine\PowerShellVersion"
$PSVersion = $PSVersionTable.GetValue("PSVersion")
Write-Host "The current PowerShell version is $PSVersion"

$latestPSVersion = winget show --id=Microsoft.PowerShell | Select-String -Pattern "^Version:" | ForEach-Object {$_.Matches.Value -replace "Version: "}
if ($PSVersion.Major -lt $latestPSVersion.Major) {
    $isElevated = ([Security.Principal.WindowsIdentity]::GetCurrent()).IsElevated
    if ($isElevated) {
        # code to install the latest version of PowerShell using winget package manager
        winget install --id=Microsoft.PowerShell -e
        # Set the installed version of PowerShell as the default
        $PSDefault = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine\PowerShellVersion" | Where-Object {$_.GetValue("PSVersion") -gt $PSVersion} | Sort-Object -Property PSVersion -Descending | Select-Object -First 1).GetValue("PSVersion")
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powershell.exe" -Name "(Default)" -Value "powershell.exe -Version $PSDefault"
        Write-Host "PowerShell has been updated to the latest version, please re-run the script using the installed powershell version to continue."
    } else {
        Write-Host "Please run the script as an Administrator to install the latest version of PowerShell and set as default"
    }
} else {
    Write-Host "PowerShell is already up to date"
    # Set the current version of PowerShell as the default
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powershell.exe" -Name "(Default)" -Value "powershell.exe -Version $PSVersion"
}

# Check if winget is installed
if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
    # Set the PowerShell Gallery repository to Trusted

powershell /c winget upgrade
powershell /c winget upgrade --all -h
$installedPackages = winget show --installed
$packagesToCheck = @("Microsoft.DesktopAppInstaller_8wekyb3d8bbwe", "Microsoft.VCRedist.2015+.x64", "Microsoft.VCRedist.2015+.x86", "DuongDieuPhap.ImageGlass", "Microsoft.Powershell", "Microsoft.DotNet.DesktopRuntime.6", "Eugeny.Tabby", "Mozilla.Firefox")
foreach ($package in $packagesToCheck) {
    if ($installedPackages -notcontains $package) {
        winget install $package
    }
}
