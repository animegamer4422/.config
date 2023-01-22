
# Create a restore point
if((Get-ComputerRestorePoint).configured -eq $false) { Enable-ComputerRestore }
Checkpoint-Computer -Description "System Restore Point before running auto-setup"

# Scoop
# Check if scoop is installed or not and install it if it isn't accordingly to the currently running session
if (!(Test-Path -Path "$env:USERPROFILE\scoop")) {
    # Check if the current session is running as an administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Download the Scoop installation script
$scoopScript = (new-object net.webclient).downloadstring('https://get.scoop.sh')

# Convert the script to a string and specify its width
$scoopScript = $scoopScript | Out-String -Width 4096

# Check if the current session is running as an administrator
if($isAdmin) {
    # Run the Scoop installation script with the -RunAsAdmin parameter
    powershell -command "& {$scoopScript -RunAsAdmin}"
} else {
    # Run the Scoop installation script without the -RunAsAdmin parameter
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
    Install-Script -Name winget -Force
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

@(set "0=%~f0"^)#) & powershell -nop -c iex([io.file]::ReadAllText($env:0)) & exit /b
#:: double-click to run or just copy-paste into powershell - it's a standalone hybrid script
sp 'HKCU:\Volatile Environment' 'Edge_Removal' @'

$also_remove_webview = 1

$host.ui.RawUI.WindowTitle = 'Edge Removal '
## targets
$remove_win32 = @("Microsoft Edge","Microsoft Edge Update"); $remove_appx = @("MicrosoftEdge")
if ($also_remove_webview -eq 1) {$remove_win32 += "Microsoft EdgeWebView"; $remove_appx += "Win32WebViewHost"}
## enable admin privileges
$D1=[uri].module.gettype('System.Diagnostics.Process')."GetM`ethods"(42) |where {$_.Name -eq 'SetPrivilege'} #`:no-ev-warn
'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege'|foreach {$D1.Invoke($null, @("$_",2))}
## set useless policies
foreach ($p in 'HKLM\SOFTWARE\Policies','HKLM\SOFTWARE') {
  cmd /c "reg add ""$p\Microsoft\EdgeUpdate"" /f /v InstallDefault /d 0 /t reg_dword >nul 2>nul"
  cmd /c "reg add ""$p\Microsoft\EdgeUpdate"" /f /v Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} /d 0 /t reg_dword >nul 2>nul"
  cmd /c "reg add ""$p\Microsoft\EdgeUpdate"" /f /v Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} /d 1 /t reg_dword >nul 2>nul"
  cmd /c "reg add ""$p\Microsoft\EdgeUpdate"" /f /v DoNotUpdateToEdgeWithChromium /d 1 /t reg_dword >nul 2>nul"
}
## clear win32 uninstall block
foreach ($hk in 'HKCU','HKLM') {foreach ($wow in '','\Wow6432Node') {foreach ($i in $remove_win32) {
  cmd /c "reg delete ""$hk\SOFTWARE${wow}\Microsoft\Windows\CurrentVersion\Uninstall\$i"" /f /v NoRemove >nul 2>nul"
}}}
## find all Edge setup.exe and gather BHO paths
$setup = @(); $bho = @(); $bho += "$env:ProgramData\ie_to_edge_stub.exe"; $bho += "$env:Public\ie_to_edge_stub.exe"
"LocalApplicationData","ProgramFilesX86","ProgramFiles" |foreach {
  $setup += dir $($([Environment]::GetFolderPath($_)) + '\Microsoft\Edge*\setup.exe') -rec -ea 0
  $bho += dir $($([Environment]::GetFolderPath($_)) + '\Microsoft\Edge*\ie_to_edge_stub.exe') -rec -ea 0
}
## shut edge down
foreach ($p in 'MicrosoftEdgeUpdate','chredge','msedge','edge','msedgewebview2','Widgets') { kill -name $p -force -ea 0 }
## use dedicated C:\Scripts path due to Sigma rules FUD
$DIR = "$env:SystemDrive\Scripts"; $null = mkdir $DIR -ea 0
## export OpenWebSearch innovative redirector
foreach ($b in $bho) { if (test-path $b) { try {copy $b "$DIR\ie_to_edge_stub.exe" -force -ea 0} catch{} } }
## clear appx uninstall block and remove
$provisioned = get-appxprovisionedpackage -online; $appxpackage = get-appxpackage -allusers
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'; $store_reg = $store.replace(':','')
$users = @('S-1-5-18'); if (test-path $store) {$users += $((dir $store |where {$_ -like '*S-1-5-21*'}).PSChildName)}
foreach ($choice in $remove_appx) { if ('' -eq $choice.Trim()) {continue}
  foreach ($appx in $($provisioned |where {$_.PackageName -like "*$choice*"})) {
    $PackageFamilyName = ($appxpackage |where {$_.Name -eq $appx.DisplayName}).PackageFamilyName; $PackageFamilyName
    cmd /c "reg add ""$store_reg\Deprovisioned\$PackageFamilyName"" /f >nul 2>nul"
    cmd /c "dism /online /remove-provisionedappxpackage /packagename:$($appx.PackageName) >nul 2>nul"
    #powershell -nop -c remove-appxprovisionedpackage -packagename "'$($appx.PackageName)'" -online 2>&1 >''
  }
  foreach ($appx in $($appxpackage |where {$_.PackageFullName -like "*$choice*"})) {
    $inbox = (gp "$store\InboxApplications\*$($appx.Name)*" Path).PSChildName
    $PackageFamilyName = $appx.PackageFamilyName; $PackageFullName = $appx.PackageFullName; $PackageFullName
    foreach ($app in $inbox) {cmd /c "reg delete ""$store_reg\InboxApplications\$app"" /f >nul 2>nul" }
    cmd /c "reg add ""$store_reg\Deprovisioned\$PackageFamilyName"" /f >nul 2>nul"
    foreach ($sid in $users) {cmd /c "reg add ""$store_reg\EndOfLife\$sid\$PackageFullName"" /f >nul 2>nul"}
    cmd /c "dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >nul 2>nul"
    powershell -nop -c "remove-appxpackage -package '$PackageFullName' -AllUsers" 2>&1 >''
    foreach ($sid in $users) {cmd /c "reg delete ""$store_reg\EndOfLife\$sid\$PackageFullName"" /f >nul 2>nul"}
  }
}
## shut edge down, again
foreach ($p in 'MicrosoftEdgeUpdate','chredge','msedge','edge','msedgewebview2','Widgets') { kill -name $p -force -ea 0 }
## brute-run found Edge setup.exe with uninstall args
$purge = '--uninstall --system-level --force-uninstall'
if ($also_remove_webview -eq 1) { foreach ($s in $setup) { try{ start -wait $s -args "--msedgewebview $purge" } catch{} } }
foreach ($s in $setup) { try{ start -wait $s -args "--msedge $purge" } catch{} }
## prevent latest cumulative update (LCU) failing due to non-matching EndOfLife Edge entries
foreach ($i in $remove_appx) {
  dir "$store\EndOfLife" -rec -ea 0 |where {$_ -like "*${i}*"} |foreach {cmd /c "reg delete ""$($_.Name)"" /f >nul 2>nul"}
  dir "$store\Deleted\EndOfLife" -rec -ea 0 |where {$_ -like "*${i}*"} |foreach {cmd /c "reg delete ""$($_.Name)"" /f >nul 2>nul"}
}
## extra cleanup
$desktop = $([Environment]::GetFolderPath('Desktop')); $appdata = $([Environment]::GetFolderPath('ApplicationData'))
del "$appdata\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Tombstones\Microsoft Edge.lnk" -force -ea 0
del "$appdata\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk" -force -ea 0
del "$desktop\Microsoft Edge.lnk" -force -ea 0

## add OpenWebSearch to redirect microsoft-edge: anti-competitive links to the default browser
$IFEO = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$MSEP = ($env:ProgramFiles,${env:ProgramFiles(x86)})[[Environment]::Is64BitOperatingSystem] + '\Microsoft\Edge\Application'
$MIN = ('--headless','--width 1 --height 1')[([environment]::OSVersion.Version.Build) -gt 25179]
$CMD = "$env:systemroot\system32\conhost.exe $MIN" # AveYo: minimize prompt - see Terminal issue #13914
cmd /c "reg add HKCR\microsoft-edge /f /ve /d URL:microsoft-edge >nul"
cmd /c "reg add HKCR\microsoft-edge /f /v ""URL Protocol"" /d """" >nul"
cmd /c "reg add HKCR\microsoft-edge /f /v NoOpenWith /d """" >nul"
cmd /c "reg add HKCR\microsoft-edge\shell\open\command /f /ve /d ""$DIR\ie_to_edge_stub.exe %1"" >nul"
cmd /c "reg add HKCR\MSEdgeHTM /f /v NoOpenWith /d """" >nul"
cmd /c "reg add HKCR\MSEdgeHTM\shell\open\command /f /ve /d ""$DIR\ie_to_edge_stub.exe %1"" >nul"
cmd /c "reg add ""$IFEO\ie_to_edge_stub.exe"" /f /v UseFilter /d 1 /t reg_dword >nul >nul"
cmd /c "reg add ""$IFEO\ie_to_edge_stub.exe\0"" /f /v FilterFullPath /d ""$DIR\ie_to_edge_stub.exe"" >nul"
cmd /c "reg add ""$IFEO\ie_to_edge_stub.exe\0"" /f /v Debugger /d ""$CMD $DIR\OpenWebSearch.cmd"" >nul"
cmd /c "reg add ""$IFEO\msedge.exe"" /f /v UseFilter /d 1 /t reg_dword >nul"
cmd /c "reg add ""$IFEO\msedge.exe\0"" /f /v FilterFullPath /d ""$MSEP\msedge.exe"" >nul"
cmd /c "reg add ""$IFEO\msedge.exe\0"" /f /v Debugger /d ""$CMD $DIR\OpenWebSearch.cmd"" >nul"

$OpenWebSearch = @$
@title OpenWebSearch Redux & echo off & set ?= open start menu web search, widgets links or help in your chosen browser
for /f %%E in ('"prompt $E$S& for %%e in (1) do rem"') do echo;%%E[2t 2>nul & rem AveYo: minimize prompt
call :reg_var "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" ProgID ProgID
if /i "%ProgID%" equ "MSEdgeHTM" echo;Default browser is set to Edge! Change it or remove OpenWebSearch script. & pause & exit /b
call :reg_var "HKCR\%ProgID%\shell\open\command" "" Browser
set Choice=& for %%. in (%Browser%) do if not defined Choice set "Choice=%%~."
call :reg_var "HKCR\MSEdgeMHT\shell\open\command" "" FallBack
set "Edge=" & for %%. in (%FallBack%) do if not defined Edge set "Edge=%%~."
set "URI=" & set "URL=" & set "NOOP=" & set "PassTrough=%Edge:msedge=edge%"
set "CLI=%CMDCMDLINE:"=``% "
if defined CLI set "CLI=%CLI:*ie_to_edge_stub.exe`` =%"
if defined CLI set "CLI=%CLI:*ie_to_edge_stub.exe =%"
if defined CLI set "CLI=%CLI:*msedge.exe`` =%"
if defined CLI set "CLI=%CLI:*msedge.exe =%"
set "FIX=%CLI:~-1%"
if defined CLI if "%FIX%"==" " set "CLI=%CLI:~0,-1%"
if defined CLI set "RED=%CLI:microsoft-edge=%"
if defined CLI set "URL=%CLI:http=%"
if defined CLI set "ARG=%CLI:``="%"
if "%CLI%" equ "%RED%" (set NOOP=1) else if "%CLI%" equ "%URL%" (set NOOP=1)
if defined NOOP if exist "%PassTrough%" start "" "%PassTrough%" %ARG%
if defined NOOP exit /b
set "URL=%CLI:*microsoft-edge=%"
set "URL=http%URL:*http=%"
set "FIX=%URL:~-2%"
if defined URL if "%FIX%"=="``" set "URL=%URL:~0,-2%"
call :dec_url
start "" "%Choice%" "%URL%"
exit

:reg_var [USAGE] call :reg_var "HKCU\Volatile Environment" value-or-"" variable [extra options]
set {var}=& set {reg}=reg query "%~1" /v %2 /z /se "," /f /e& if %2=="" set {reg}=reg query "%~1" /ve /z /se "," /f /e
for /f "skip=2 tokens=* delims=" %%V in ('%{reg}% %4 %5 %6 %7 %8 %9 2^>nul') do if not defined {var} set "{var}=%%V"
if not defined {var} (set {reg}=& set "%~3="& exit /b) else if %2=="" set "{var}=%{var}:*)    =%"& rem AveYo: v3
if not defined {var} (set {reg}=& set "%~3="& exit /b) else set {reg}=& set "%~3=%{var}:*)    =%"& set {var}=& exit /b

:dec_url brute url percent decoding  
set ".=%URL:!=}%"&setlocal enabledelayedexpansion& rem brute url percent decoding
set ".=!.:%%={!" &set ".=!.:{3A=:!" &set ".=!.:{2F=/!" &set ".=!.:{3F=?!" &set ".=!.:{23=#!" &set ".=!.:{5B=[!" &set ".=!.:{5D=]!"
set ".=!.:{40=@!"&set ".=!.:{21=}!" &set ".=!.:{24=$!" &set ".=!.:{26=&!" &set ".=!.:{27='!" &set ".=!.:{28=(!" &set ".=!.:{29=)!"
set ".=!.:{2A=*!"&set ".=!.:{2B=+!" &set ".=!.:{2C=,!" &set ".=!.:{3B=;!" &set ".=!.:{3D==!" &set ".=!.:{25=%%!"&set ".=!.:{20= !"
set ".=!.:{=%%!" &rem set ",=!.:%%=!" & if "!,!" neq "!.!" endlocal& set "URL=%.:}=!%" & call :dec_url
endlocal& set "URL=%.:}=!%" & exit /b
rem done

$@
[io.file]::WriteAllText("$DIR\OpenWebSearch.cmd", $OpenWebSearch) >''
## cleanup
$cleanup = gp 'Registry::HKEY_Users\S-1-5-21*\Volatile*' Edge_Removal -ea 0
if ($cleanup) {rp $cleanup.PSPath Edge_Removal -force -ea 0}


write-host -nonew -fore green -back black "`n EDGE REMOVED!"; 
exit

## ask to run script as admin
'@.replace("$@","'@").replace("@$","@'") -force -ea 0;
$A = '-nop -noe -c & {iex((gp ''Registry::HKEY_Users\S-1-5-21*\Volatile*'' Edge_Removal -ea 0)[0].Edge_Removal)}'
start powershell -args $A -verb runas
$_Press_Enter
#::

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
